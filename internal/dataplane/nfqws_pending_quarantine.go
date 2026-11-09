package dataplane

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"sync"
)

// NFQWSPendingQuarantine is issued by the SAME original Manager operation
// after whole-transaction classification, never by a journal/DTO constructor.
// It grants no effect and cannot clear a Gate fence. The App must continuously
// retain its already-held exclusive admission until this exact owner joins.
type NFQWSPendingQuarantine struct {
	mu        sync.Mutex
	self      *NFQWSPendingQuarantine
	manager   *Manager
	scope     *executionResourceScope
	execution *nfqws2ActiveExecution
	plan      Plan
	records   *xraySelectedTCPExecutionRecords
	planFile  *os.File
	planInfo  os.FileInfo
	planRaw   []byte
	terminal  []byte
	revoked   error
	claimed   bool
	joined    bool
	closed    bool
	closeErr  error
}

func (*NFQWSPendingQuarantine) String() string   { return "[original pending NFQ transaction]" }
func (*NFQWSPendingQuarantine) GoString() string { return "[original pending NFQ transaction]" }

func (q *NFQWSPendingQuarantine) revokeLocked(err error) {
	q.revoked = errors.Join(q.revoked, ErrExecutionJournal, err)
}

// Revoke can only remove eligibility; it never destroys original cleanup
// custody or turns a failed journal into a release permission.
func (q *NFQWSPendingQuarantine) Revoke() {
	if q == nil {
		return
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	q.revokeLocked(ErrExecutionJournal)
}

// The Manager calls this once, before the final pending publications, only
// after all other rollback actions and uncertainty have been classified.
func newNFQWSPendingQuarantine(ctx context.Context, m *Manager, s *executionResourceScope, plan Plan) (*NFQWSPendingQuarantine, error) {
	if ctx == nil || ctx.Err() != nil || m == nil || s == nil || s.nfqQuarantine != nil {
		return nil, ErrNFQWSScopedOwner
	}
	e, ok := ctx.Value(nfqws2ActiveExecutionKey{}).(*nfqws2ActiveExecution)
	if !ok || e == nil || e.self != e || e.material == nil || e.material.manager != m || e.resource == nil || e.resource.scope != s || !nfqws2ActiveSamePlan(e.plan, plan) || e.panel == nil || e.panel.Err() != nil {
		return nil, ErrNFQWSScopedOwner
	}
	s.mu.Lock()
	err := s.checkOriginalOwner(ctx, nil, false, true)
	valid := s.failure == nil && s.open && !s.retained && s.manager == m && s.adapterOwner == e.material.adapter
	s.mu.Unlock()
	if !valid || err != nil {
		return nil, errors.Join(ErrNFQWSScopedOwner, err)
	}
	if err := e.reviewNeverIssuedPendingPrefix(ctx); err != nil {
		return nil, err
	}
	records, err := newNFQWSProbeRecords(s)
	if err != nil {
		return nil, err
	}
	q := &NFQWSPendingQuarantine{manager: m, scope: s, execution: e, plan: cloneExecutionResourcePlan(plan), records: records}
	q.self = q
	if err := records.beforePublication(); err != nil {
		return nil, errors.Join(err, records.close())
	}
	return q, nil
}

// This establishes current known ownership, not a new rollback capability.
// Unknown started/lost-ACK or any entered cleanup stays permanently fenced.
func (e *nfqws2ActiveExecution) reviewNeverIssuedPendingPrefix(ctx context.Context) error {
	e.mu.Lock()
	c := e.partialRecovery
	e.mu.Unlock()
	o, ownerErr := e.owner()
	if ownerErr != nil {
		return ownerErr
	}
	o.mu.Lock()
	retiring := o.retirementStarted
	o.mu.Unlock()
	if c == nil || retiring {
		return ErrPolicyAdditionUnknown
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.self != c || c.execution != e || !c.retained || c.entered || c.closed || c.fenced || c.session == nil || c.index < 0 || c.index >= len(c.session.doc.Steps) || c.session.doc.Phase != "active" || c.pending != nil || c.scope.Load() != nil {
		return ErrPolicyAdditionUnknown
	}
	for i, step := range c.session.doc.Steps {
		want := "planned"
		if i < c.index {
			want = "added"
		}
		if i == c.index {
			want = "intent"
			if c.settled {
				want = "removed"
			}
		}
		if step.State != want {
			return ErrPolicyAdditionUnknown
		}
	}
	scope := &nfqwsRecoveryScope{owner: c}
	scope.self = scope
	c.scope.Store(scope)
	defer func() {
		scope.closed.Store(true)
		scope.readers.Lock()
		c.scope.Store(nil)
		scope.readers.Unlock()
	}()
	ctx = context.WithValue(ctx, nfqwsPolicyRecoveryKey{}, scope)
	ctx = context.WithValue(ctx, policyEffectReceiptBorrowKey{}, c.session.borrow)
	return e.verifyNeverIssuedPrefix(ctx, c)
}

// ReviewPendingNFQWSQuarantine returns only the private whole-transaction
// witness already minted by this actual Apply. It cannot inspect a persisted
// unknown generation to reconstruct custody or revoke a permanent fence.
func (m *Manager) ReviewPendingNFQWSQuarantine(ctx context.Context) (*NFQWSPendingQuarantine, error) {
	if m == nil || ctx == nil || ctx.Err() != nil {
		return nil, ErrNFQWSScopedOwner
	}
	m.retainedNFQMu.Lock()
	p := m.pendingNFQ
	m.retainedNFQMu.Unlock()
	if p == nil || p.self != p || p.blocked != nil || p.conflict != nil || p.scope == nil || !p.claim.original(m, p.execution, p.scope) || ctx.Value(nfqws2ActiveExecutionKey{}) != p.execution {
		return nil, ErrNFQWSScopedOwner
	}
	q := p.scope.nfqQuarantine
	if q == nil || q.self != q || q.manager != m || q.scope != p.scope || q.execution != p.execution || q.execution.cleanup == nil {
		return nil, ErrNFQWSScopedOwner
	}
	err := q.execution.cleanup.WithCurrent(ctx, func() error {
		q.mu.Lock()
		defer q.mu.Unlock()
		if q.claimed || q.joined || q.closed || q.revoked != nil {
			return ErrExecutionJournal
		}
		if err := q.recordsCurrentLocked(ctx); err != nil {
			q.revokeLocked(err)
			return err
		}
		if q.scope.execution == nil || q.scope.execution.State != "rollback-failed" || q.scope.execution.RollbackVerified || q.plan.State != "rollback-failed" {
			q.revokeLocked(ErrExecutionJournal)
			return ErrExecutionJournal
		}
		executionRaw, executionErr := json.Marshal(q.scope.execution)
		planRaw, planErr := json.MarshalIndent(q.plan, "", "  ")
		if executionErr != nil || planErr != nil || !bytes.Equal(executionRaw, q.records.images[0]) || !bytes.Equal(executionRaw, q.records.images[1]) || !bytes.Equal(planRaw, q.planRaw) {
			q.revokeLocked(errors.Join(executionErr, planErr))
			return ErrExecutionJournal
		}
		q.claimed = true
		return nil
	})
	if err != nil {
		q.mu.Lock()
		q.claimed = false
		q.revokeLocked(err)
		q.mu.Unlock()
		return nil, err
	}
	return q, nil
}

// sealJoined runs in the original Manager retry before original scope close.
// Only its actual complete rollback and three successful authored publications
// may create terminal knowledge; no App-provided Execution is accepted.
func (q *NFQWSPendingQuarantine) sealJoined(ctx context.Context, execution Execution, plan Plan) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.self != q || q.closed || !q.claimed || q.joined || execution.State != "rolled-back" || !execution.RollbackVerified || validateExecutionResources(execution, true) != nil || plan.State != "rolled-back" || plan.PlanID != q.plan.PlanID || plan.Digest != q.plan.Digest || plan.Revision != q.plan.Revision || q.scope.execution == nil || !reflect.DeepEqual(*q.scope.execution, execution) {
		q.revokeLocked(ErrExecutionJournal)
		return ErrExecutionJournal
	}
	if err := q.recordsCurrentLocked(ctx); err != nil {
		q.revokeLocked(err)
		return err
	}
	canonical, err := json.Marshal(execution)
	if err != nil || !bytes.Equal(canonical, q.records.images[0]) || !bytes.Equal(canonical, q.records.images[1]) {
		q.revokeLocked(err)
		return ErrExecutionJournal
	}
	wanted, err := json.MarshalIndent(plan, "", "  ")
	if err != nil || !bytes.Equal(wanted, q.planRaw) {
		q.revokeLocked(err)
		return ErrExecutionJournal
	}
	q.terminal, q.joined = bytes.Clone(canonical), true
	return nil
}

// Joined verifies the SAME terminal publication custody while the original
// exclusive cleanup admission is still held. It does not release that lease.
func (q *NFQWSPendingQuarantine) Joined(ctx context.Context) error {
	return q.joinedCurrent(ctx, false)
}

// VerifyJoinedCleanup verifies terminal cleanup knowledge even after admission
// eligibility was irrevocably revoked. The App must already be permanently
// fenced; this method grants no open admission and cannot clear that fence.
func (q *NFQWSPendingQuarantine) VerifyJoinedCleanup(ctx context.Context) error {
	return q.joinedCurrent(ctx, true)
}

func (q *NFQWSPendingQuarantine) joinedCurrent(ctx context.Context, cleanupOnly bool) error {
	if q == nil || q.self != q || ctx == nil || ctx.Value(nfqws2ActiveExecutionKey{}) != q.execution || q.execution.cleanup == nil {
		return ErrNFQWSScopedOwner
	}
	return q.execution.cleanup.WithCurrent(ctx, func() error {
		q.mu.Lock()
		defer q.mu.Unlock()
		if !q.claimed || !q.joined || q.closed || !cleanupOnly && q.revoked != nil || len(q.terminal) == 0 {
			return ErrExecutionJournal
		}
		if err := q.recordsCurrentLocked(ctx); err != nil {
			q.revokeLocked(err)
			return err
		}
		if !bytes.Equal(q.terminal, q.records.images[0]) || !bytes.Equal(q.terminal, q.records.images[1]) {
			q.revokeLocked(ErrExecutionJournal)
			return ErrExecutionJournal
		}
		return nil
	})
}

// Close releases only held journal descriptors, never Gate admission. Failure
// must be promoted to the existing permanent fence by the original App owner.
func (q *NFQWSPendingQuarantine) Close() error {
	if q == nil || q.self != q {
		return ErrExecutionJournal
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.closeLocked()
}

// No ID/DTO match substitutes for the exact two original participants.
func originalNFQQuarantineParticipants(ctx context.Context, prepared []Adapter, gate Adapter, s *executionResourceScope) bool {
	if ctx == nil || s == nil || len(prepared) != 2 {
		return false
	}
	e, _ := ctx.Value(nfqws2ActiveExecutionKey{}).(*nfqws2ActiveExecution)
	if e == nil || e.self != e || e.material == nil || e.gate == nil || gate != e.gate || s.adapterOwner != e.material.adapter {
		return false
	}
	nfq, lan := 0, 0
	for _, adapter := range prepared {
		switch adapter {
		case e.material.adapter:
			nfq++
		case e.gate:
			lan++
		default:
			return false
		}
	}
	return nfq == 1 && lan == 1
}

func (q *NFQWSPendingQuarantine) claimedByApp() bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.self == q && q.claimed
}
