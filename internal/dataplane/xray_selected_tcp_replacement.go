package dataplane

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"reflect"
	"sync/atomic"

	"github.com/ArtixSx/razvilka/internal/operationgate"
)

// A sealed association of two actual issuers, never a journal/owner DTO. A
// remains unchanged through candidate health, Store CAS and final two-writer
// ACK. Only then may original A retirement remove A selectors/process/flows.
type xraySelectedTCPReplacement struct {
	self       *xraySelectedTCPReplacement
	manager    *Manager
	prior      *retainedXrayExecution
	candidate  *xraySelectedTCPExecution
	scope      *executionResourceScope
	records    *xraySelectedTCPExecutionRecords
	cleanup    *operationgate.ExclusiveCleanupReview
	gateBefore *networkPolicyGateState
	priorPlan  Plan
	retry      func(context.Context) error
	handedOver atomic.Bool
	priorAlias atomic.Bool
	committed  atomic.Bool
	pending    atomic.Bool
	stopping   atomic.Bool
	closed     atomic.Bool
}
type xraySelectedTCPReplacementKey struct{}

func xraySelectedTCPAssociated(current, expected *xraySelectedTCPExecution) bool {
	if current == expected {
		return current != nil
	}
	return current != nil && current.self == current && current.replacement != nil && current.replacement.self == current.replacement &&
		!current.replacement.closed.Load() && current.replacement.candidate == current && current.replacement.prior != nil && current.replacement.prior.execution == expected
}

func xraySelectedTCPSameReplacementIntent(a, c XraySelectedTCPRedirectSpec) bool {
	if _, err := canonicalXraySelectedTCPRedirect(a); err != nil {
		return false
	}
	if _, err := canonicalXraySelectedTCPRedirect(c); err != nil {
		return false
	}
	if a.ServiceID != c.ServiceID || a.NodeID == c.NodeID || a.Generation == c.Generation || a.Listener.Addr() != c.Listener.Addr() || a.Listener.Port() == c.Listener.Port() ||
		!((a.Listener.Port() == 16443 && c.Listener.Port() == 16444) || (a.Listener.Port() == 16444 && c.Listener.Port() == 16443)) {
		return false
	}
	a.NodeID, a.Generation, a.Listener = c.NodeID, c.Generation, c.Listener
	a.LAN, c.LAN = CloneLANPolicyRuntime(a.LAN), CloneLANPolicyRuntime(c.LAN)
	if a.LAN == nil || c.LAN == nil {
		return false
	}
	a.LAN.Generation = c.LAN.Generation
	a.LAN.Digest = lanPolicyDigest(a.LAN)
	return reflect.DeepEqual(a, c)
}

// expectedPrior is comparison only. The Manager selects its actual original
// retained owner, validates its structural cleanup lane and complete writers;
// old A's now-failed/expired PASS is never used for candidate admission.
func (m *XrayOperationMaterial) BindReplacementExecution(ctx, panel context.Context, expectedPrior, candidate Plan, inventory *BackendInventory, gate *NetworkPolicyAdapter, checks *NetworkPolicyChecks, committed, cleanupGuard XraySelectedTCPActiveGuard) (context.Context, error) {
	if m == nil || m.self != m || m.material == nil || xraySelectedTCPFinite(ctx) != nil || m.manager == nil || ctx.Value(xraySelectedTCPReplacementKey{}) != nil {
		return nil, ErrXrayOperationOwner
	}
	manager := m.manager
	if err := manager.beginOperation(ctx); err != nil {
		return nil, err
	}
	defer manager.endOperation()
	a := manager.retainedXrayOwner()
	if a == nil || a.self != a || a.pending || a.execution == nil || a.execution.self != a.execution || a.execution.resource == nil || a.execution.material.adapter != m.adapter ||
		a.execution.material.control != m.control || a.execution.gate != gate || a.execution.checks != checks || a.execution.panel != panel ||
		a.execution.plan.NetworkProfileID != candidate.NetworkProfileID || !xraySelectedTCPSamePlan(a.execution.plan, expectedPrior) || !xraySelectedTCPSameReplacementIntent(a.execution.material.material.spec, m.material.spec) {
		return nil, ErrXrayOperationOwner
	}
	p := &xraySelectedTCPReplacement{manager: manager, prior: a, cleanup: m.cleanup}
	p.self = p
	if err := p.priorStructural(ctx); err != nil {
		return nil, err
	}
	var err error
	p.gateBefore, err = gate.readOwner()
	if err != nil || p.gateBefore == nil || !p.gateBefore.Promoted || p.gateBefore.PromotionPending || p.gateBefore.PlanID != a.execution.plan.PlanID || p.gateBefore.Digest != a.execution.plan.Digest || !reflect.DeepEqual(p.gateBefore.LAN, a.execution.plan.LAN) {
		return nil, errors.Join(ErrXrayOperationOwner, err)
	}
	p.priorPlan, _, err = manager.committedLocked()
	if err != nil || p.priorPlan.State != "committed" || !xraySelectedTCPSamePlan(expectedPrior, p.priorPlan) {
		return nil, errors.Join(ErrXrayOperationOwner, err)
	}
	manager.retainedXrayMu.Lock()
	if manager.retainedXray != a || manager.replacementXray != nil {
		manager.retainedXrayMu.Unlock()
		return nil, ErrXrayOperationOwner
	}
	manager.replacementXray = p
	manager.retainedXrayMu.Unlock()
	ctx, err = m.bindExecution(ctx, panel, candidate, inventory, gate, checks, committed, cleanupGuard, p)
	if err != nil {
		manager.retainedXrayMu.Lock()
		manager.replacementXray = nil
		manager.retainedXrayMu.Unlock()
		return nil, err
	}
	a.execution.replacement = p
	a.records.replacement.Store(p)
	return context.WithValue(ctx, xraySelectedTCPReplacementKey{}, p), nil
}

func (m *Manager) xrayReplacementFor(ctx context.Context, plan Plan) (*xraySelectedTCPReplacement, error) {
	m.retainedXrayMu.Lock()
	p := m.replacementXray
	m.retainedXrayMu.Unlock()
	if p == nil {
		if ctx != nil && ctx.Value(xraySelectedTCPReplacementKey{}) != nil {
			return nil, ErrXrayOperationOwner
		}
		return nil, nil
	}
	if ctx == nil || ctx.Value(xraySelectedTCPReplacementKey{}) != p || p.self != p || p.manager != m || p.closed.Load() || p.pending.Load() || p.candidate == nil ||
		ctx.Value(xraySelectedTCPExecutionKey{}) != p.candidate || !xraySelectedTCPSamePlan(p.candidate.plan, plan) || xraySelectedTCPFinite(ctx) != nil {
		return nil, ErrXrayOperationOwner
	}
	return p, nil
}

// Bind claimed two actual issuers before Apply. If its original operation is
// cancelled before Manager entry, keep that exact association for finite join;
// no competing Manager operation may be compensated outside its serial lock.
func (m *Manager) pendingUnenteredXrayReplacement(ctx context.Context, plan Plan) bool {
	if m == nil || ctx == nil {
		return false
	}
	m.retainedXrayMu.Lock()
	defer m.retainedXrayMu.Unlock()
	p := m.replacementXray
	if p == nil || p.self != p || p.manager != m || p.closed.Load() || p.candidate == nil || p.prior == nil || ctx.Value(xraySelectedTCPReplacementKey{}) != p || ctx.Value(xraySelectedTCPExecutionKey{}) != p.candidate || !xraySelectedTCPSamePlan(p.candidate.plan, plan) {
		return false
	}
	p.pending.Store(true)
	return true
}

func (p *xraySelectedTCPReplacement) priorContext(ctx context.Context) (context.Context, func(), error) {
	if p == nil || p.self != p || p.closed.Load() || p.prior == nil || p.prior.self != p.prior || p.prior.execution == nil || p.cleanup == nil || xraySelectedTCPFinite(ctx) != nil {
		return nil, nil, ErrXrayOperationOwner
	}
	ctx = context.WithValue(ctx, xraySelectedTCPReplacementKey{}, p)
	return p.prior.operation(ctx, p.cleanup, false)
}

func (p *xraySelectedTCPReplacement) priorStructural(ctx context.Context) error {
	c, closeOperation, err := p.priorContext(ctx)
	if err != nil {
		return err
	}
	defer closeOperation()
	e, r := p.prior.execution, p.prior.execution.resource
	if r == nil || r.stopped || r.descriptorsClosed || e.retired || !r.active || e.owners(c) != nil || r.owner.checkHeld(c, true) != nil {
		return ErrXrayOperationOwner
	}
	if err := r.originalListenerCurrent(c, true); err != nil {
		return err
	}
	r.commonMu.Lock()
	publication := r.common
	err = ErrPolicyAdditionReceipt
	if publication != nil && publication.status.Complete && !publication.status.Removed && !publication.status.Unknown && !publication.status.Promoted {
		err = publication.current(c)
	}
	r.commonMu.Unlock()
	if err != nil {
		return err
	}
	return errors.Join(p.prior.records.current(c, true), r.configCurrent(c), r.executable.current(c))
}

func newXraySelectedTCPRecords(s *executionResourceScope) (*xraySelectedTCPExecutionRecords, error) {
	if s == nil || s.manager == nil || s.managerRoot != s.manager.StateRoot || s.root != filepath.Join(s.managerRoot, "transactions", s.plan.PlanID) {
		return nil, ErrExecutionJournal
	}
	d := &xraySelectedTCPExecutionRecords{scope: s}
	var err error
	d.root, d.anchor, err = openNetworkPolicyObservationRoot(s.managerRoot)
	if err == nil {
		d.transactionRoot, d.transactionAnchor, err = openNetworkPolicyObservationRoot(s.root)
	}
	if err != nil {
		return nil, errors.Join(err, d.close())
	}
	return d, nil
}

func (p *xraySelectedTCPReplacement) attachScope(s *executionResourceScope) error {
	if p == nil || p.self != p || p.scope != nil || s == nil || s.manager != p.manager || p.candidate == nil || !xraySelectedTCPSamePlan(s.plan, p.candidate.plan) {
		return ErrXrayOperationOwner
	}
	d, err := newXraySelectedTCPRecords(s)
	if err != nil {
		return err
	}
	p.scope, p.records = s, d
	return nil
}

func (p *xraySelectedTCPReplacement) latestCurrent(ctx context.Context) error {
	if p == nil || p.self != p || p.manager == nil || p.closed.Load() || !p.handedOver.Load() || p.records == nil || p.records.scope != p.scope {
		return ErrExecutionJournal
	}
	p.manager.retainedXrayMu.Lock()
	original := p.manager.replacementXray == p
	p.manager.retainedXrayMu.Unlock()
	if !original {
		return ErrExecutionJournal
	}
	return p.records.current(ctx, false)
}

func (p *xraySelectedTCPReplacement) publish(s *executionResourceScope, data []byte) error {
	if p == nil || p.self != p || p.closed.Load() || p.scope == nil || p.records == nil || s == nil || s.manager != p.manager ||
		p.prior == nil || p.prior.records == nil || (s != p.scope && s != p.prior.scope) {
		return ErrExecutionJournal
	}
	d := p.records
	if s == p.prior.scope {
		if !p.committed.Load() {
			return ErrExecutionJournal
		}
		d = p.prior.records
	}
	if err := d.beforePublication(); err != nil {
		return err
	}
	if s == p.scope {
		if err := p.prior.records.beforePublication(); err != nil {
			return err
		}
	}
	first := p.publishWriter(s, d, data, 0)
	second := p.publishWriter(s, d, data, 1)
	return errors.Join(first, second)
}

// These are the same original two writers used after the full bookend above.
// Each successful capture retains its own actual FD even if the other fails.
func (p *xraySelectedTCPReplacement) publishWriter(s *executionResourceScope, d *xraySelectedTCPExecutionRecords, data []byte, index int) error {
	if p == nil || p.self != p || p.closed.Load() || p.prior == nil || index < 0 || index > 1 ||
		(s != p.scope || d != p.records) && (s != p.prior.scope || d != p.prior.records || !p.committed.Load()) {
		return ErrExecutionJournal
	}
	root, name := d.recordPath(index)
	path := filepath.Join(s.root, name)
	if index == 1 && s == p.scope {
		path = filepath.Join(p.manager.StateRoot, "latest-execution.json")
	}
	if index == 1 && s == p.prior.scope {
		root, name = d.transactionRoot, "replacement-execution.json"
		path = filepath.Join(s.root, name)
	}
	file, err := writeDataplaneJournalRetained(path, data)
	if err != nil {
		return err
	}
	info, err := file.Stat()
	if err == nil {
		err = d.captureOriginalRecord(index, file, info, data, root, name)
	}
	if err != nil {
		return errors.Join(err, file.Close())
	}
	if index == 1 {
		if s == p.scope {
			p.handedOver.Store(true)
		} else {
			p.priorAlias.Store(true)
		}
	}
	return nil
}

func (p *xraySelectedTCPReplacement) publishPriorLatest() error {
	if p == nil || p.self != p || p.closed.Load() || p.manager == nil || p.prior == nil || p.prior.records == nil || p.prior.scope == nil {
		return ErrExecutionJournal
	}
	d := p.prior.records
	if p.priorAlias.Load() {
		return ErrExecutionJournal // A retirement has begun; restoration is gone.
	}
	if err := d.beforePublication(); err != nil {
		return err
	}
	data, err := json.Marshal(p.prior.scope.execution)
	if err != nil {
		return err
	}
	file, err := writeDataplaneJournalRetained(filepath.Join(p.manager.StateRoot, "latest-execution.json"), data)
	if err != nil {
		return err
	}
	info, err := file.Stat()
	if err == nil {
		err = d.captureOriginalRecord(1, file, info, data, d.root, "latest-execution.json")
	}
	if err != nil {
		return errors.Join(err, file.Close())
	}
	p.handedOver.Store(false)
	return nil
}

// Only after C's committed Store image and both actual journal ACKs. This
// removes A's selectors first, joins ONLY old A's listener/flows and sole Wait,
// and leaves C's gate and original COMMON untouched throughout retirement.
func (p *xraySelectedTCPReplacement) retirePrior(ctx context.Context) error {
	if p == nil || p.self != p || !p.committed.Load() || p.candidate == nil || p.records == nil || p.candidateCurrent(ctx) != nil {
		return ErrXrayOperationOwner
	}
	c, closeOperation, err := p.priorContext(ctx)
	if err != nil {
		return err
	}
	defer closeOperation()
	if err := p.prior.execution.rollback(c); err != nil {
		return err
	}
	if ok, err := p.prior.execution.verifyRollback(c); err != nil || !ok {
		return errors.Join(ErrPolicyAdditionUnknown, err)
	}
	if err := p.prior.records.current(c, true); err != nil {
		return err
	}
	if err := p.candidateCurrent(ctx); err != nil {
		return err
	}
	if err := p.prior.scope.close(); err != nil {
		return err
	}
	return p.clear(false)
}

// The actual retained C owner closes health, node origin, Store, control,
// physical incarnation and both original writers around irreversible A join.
// No original A PASS or new C process is issued by this read operation.
func (p *xraySelectedTCPReplacement) candidateCurrent(ctx context.Context) error {
	if p == nil || p.self != p || p.closed.Load() || p.manager == nil || p.candidate == nil || p.records == nil {
		return ErrXrayOperationOwner
	}
	o := p.manager.retainedXrayOwner()
	if o == nil || o.self != o || o.pending || o.execution != p.candidate || o.scope != p.scope || o.records != p.records {
		return ErrXrayOperationOwner
	}
	if p.stopping.Load() {
		if !p.pending.Load() || p.cleanup == nil {
			return ErrXrayOperationOwner
		}
		c, end, err := o.operation(ctx, p.cleanup, false)
		if err != nil {
			return err
		}
		defer end()
		r := o.execution.resource
		if r == nil || r.descriptorsClosed || r.owner.checkHeld(c, true) != nil || o.execution.owners(c) != nil || r.configCurrent(c) != nil || r.executable.current(c) != nil {
			return ErrXrayOperationOwner
		}
		r.commonMu.Lock()
		publication := r.common
		err = ErrPolicyAdditionReceipt
		if publication != nil && publication.status.Complete && !publication.status.Removed && !publication.status.Unknown && !publication.status.Promoted {
			err = publication.current(c)
		}
		r.commonMu.Unlock()
		if err != nil {
			return err
		}
		return p.records.current(c, true)
	}
	c, end, err := o.operation(ctx, nil, true)
	if err != nil {
		return err
	}
	defer end()
	if err := p.records.current(c, true); err != nil {
		return err
	}
	if err := o.execution.health(c); err != nil {
		return err
	}
	return p.records.current(c, true)
}

func (p *xraySelectedTCPReplacement) clear(restored bool) error {
	p.manager.retainedXrayMu.Lock()
	defer p.manager.retainedXrayMu.Unlock()
	if p.manager.replacementXray != p {
		return ErrXrayOperationOwner
	}
	xraySelectedTCPExecutions.Lock()
	if xraySelectedTCPExecutions.live[p.candidate.material.adapter] != p.candidate {
		xraySelectedTCPExecutions.Unlock()
		return ErrXrayOperationOwner
	}
	if restored {
		p.manager.retainedXray = p.prior
		xraySelectedTCPExecutions.live[p.candidate.material.adapter] = p.prior.execution
		p.prior.execution.replacement = nil
	}
	xraySelectedTCPExecutions.Unlock()
	p.manager.replacementXray = nil
	p.prior.records.replacement.Store(nil)
	p.closed.Store(true)
	return nil
}

func (p *xraySelectedTCPReplacement) settleApply(ctx context.Context, result *Execution, resultErr *error) {
	if p == nil || p.self != p || p.closed.Load() {
		return
	}
	cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), p.manager.rollbackTimeout())
	defer cancel()
	var err error
	if result.State == "committed" && *resultErr == nil {
		p.committed.Store(true)
		err = p.retirePrior(cleanup)
	} else if result.State != "rollback-failed" {
		err = p.restorePrior(cleanup)
	} else {
		err = ErrPolicyAdditionUnknown
	}
	if err != nil {
		p.pending.Store(true)
		result.State, result.RollbackVerified = "replacement-pending", false
		*resultErr = errors.Join(*resultErr, err)
	}
}

// The candidate's original full Manager undo executes before this function.
// Original A remained live; restore uses its actual writers and exact retained
// gate preimage. No Start/add command or new service proof is issued for A.
func (p *xraySelectedTCPReplacement) restorePrior(ctx context.Context) error {
	if p.committed.Load() {
		return ErrXrayOperationOwner
	}
	e := p.candidate
	if e == nil || e.self != e {
		return ErrXrayOperationOwner
	}
	if err := e.rollback(ctx); err != nil {
		return err
	}
	if ok, err := e.verifyRollback(ctx); err != nil || !ok {
		return errors.Join(ErrPolicyAdditionUnknown, err)
	}
	if err := p.priorStructural(ctx); err != nil {
		return err
	}
	owner, err := e.gate.readOwner()
	if err != nil || !reflect.DeepEqual(owner, p.gateBefore) {
		return errors.Join(ErrXrayOperationOwner, err)
	}
	if err := p.manager.recordLocked(cloneExecutionResourcePlan(p.priorPlan)); err != nil {
		return err
	}
	if p.handedOver.Load() {
		if err := p.publishPriorLatest(); err != nil {
			return err
		}
	}
	if p.scope != nil {
		if err := p.scope.close(); err != nil {
			return err
		}
	}
	if e.resource == nil && p.records != nil {
		if err := p.records.close(); err != nil {
			return err
		}
	}
	return p.clear(true)
}

// Reuses the actual finite pending operation retained by App. It can only
// complete the original full rollback or postcommit retirement, never apply
// another candidate or re-open a physical/node/source review.
func (m *Manager) JoinPendingManagedXrayReplacement(ctx context.Context, forStop ...bool) (bool, error) {
	if len(forStop) > 1 {
		return false, ErrXrayOperationOwner
	}
	if err := m.beginOperation(ctx); err != nil {
		return false, err
	}
	defer m.endOperation()
	m.retainedXrayMu.Lock()
	p := m.replacementXray
	m.retainedXrayMu.Unlock()
	if p == nil || p.self != p || !p.pending.Load() || ctx == nil || ctx.Value(xraySelectedTCPReplacementKey{}) != p || ctx.Value(xraySelectedTCPExecutionKey{}) != p.candidate {
		return false, ErrXrayOperationOwner
	}
	if p.committed.Load() {
		stop := len(forStop) == 1 && forStop[0]
		if p.stopping.Load() && !stop {
			return false, ErrXrayOperationOwner
		}
		if stop {
			if p.cleanup == nil || p.candidate.material == nil || p.candidate.cleanupGuard == nil {
				return false, ErrXrayOperationOwner
			}
			if err := p.cleanup.WithCurrent(ctx, func() error {
				if err := p.candidate.material.control.CurrentForCleanupOperation(ctx, p.cleanup); err != nil {
					return err
				}
				return p.candidate.cleanupGuard(ctx, p.candidate.plan)
			}); err != nil {
				return false, err
			}
			p.stopping.Store(true) // Revokes this pair's forward completion lane.
		}
		return true, p.retirePrior(ctx)
	}
	if o := m.retainedXrayOwner(); o != nil && o != p.prior && o.join != nil {
		c, end, err := o.operation(ctx, p.cleanup, false)
		if err != nil {
			return false, err
		}
		defer end()
		if err := o.join(c); err != nil {
			return false, err
		}
		return false, p.restorePrior(c)
	}
	if p.retry != nil {
		if err := p.retry(ctx); err != nil {
			return false, err
		}
	}
	return false, p.restorePrior(ctx)
}

func (m *Manager) hasPendingXrayReplacement() bool {
	m.retainedXrayMu.Lock()
	defer m.retainedXrayMu.Unlock()
	return m.replacementXray != nil && m.replacementXray.pending.Load()
}

func (a *NetworkPolicyAdapter) replacement(ctx context.Context, plan Plan) (*xraySelectedTCPReplacement, error) {
	if ctx == nil {
		return nil, ErrXrayOperationOwner
	}
	value := ctx.Value(xraySelectedTCPReplacementKey{})
	if value == nil {
		return nil, nil
	}
	p, ok := value.(*xraySelectedTCPReplacement)
	if !ok || p == nil || p.self != p || p.closed.Load() || p.manager == nil || p.candidate == nil || p.candidate.gate != a || xraySelectedTCPFinite(ctx) != nil {
		return nil, ErrXrayOperationOwner
	}
	p.manager.retainedXrayMu.Lock()
	original := p.manager.replacementXray == p
	p.manager.retainedXrayMu.Unlock()
	comparison := cloneExecutionResourcePlan(plan)
	comparison.Ready = p.candidate.plan.Ready // Original rollback revokes forward readiness.
	if !original || !xraySelectedTCPSamePlan(p.candidate.plan, comparison) {
		return nil, ErrXrayOperationOwner
	}
	return p, nil
}

func (c *NetworkPolicyChecks) xrayReplacement(ctx context.Context) (*xraySelectedTCPReplacement, error) {
	if c == nil || ctx == nil {
		return nil, ErrNetworkPolicyConsumers
	}
	p, ok := ctx.Value(xraySelectedTCPReplacementKey{}).(*xraySelectedTCPReplacement)
	if !ok || p == nil || p.self != p || p.closed.Load() || p.manager == nil || p.manager != c.manager || p.candidate == nil || p.candidate.checks != c || p.prior == nil || p.prior.execution == nil || p.prior.execution.checks != c {
		return nil, ErrNetworkPolicyConsumers
	}
	p.manager.retainedXrayMu.Lock()
	original := p.manager.replacementXray == p
	p.manager.retainedXrayMu.Unlock()
	if !original || xraySelectedTCPFinite(ctx) != nil {
		return nil, ErrNetworkPolicyConsumers
	}
	return p, nil
}

// A failed candidate can own only the early original journal scope before its
// resource issuer publishes anything. This proves no C native/effect attempt;
// it never treats original A as globally inactive or adopts a journal DTO.
func (p *xraySelectedTCPReplacement) unusedCandidate(ctx context.Context, e *xraySelectedTCPExecution) error {
	if p == nil || p.self != p || p.closed.Load() || p.committed.Load() || p.candidate != e || e == nil || e.self != e || e.material == nil || e.material.execution != e ||
		ctx == nil || ctx.Value(xraySelectedTCPReplacementKey{}) != p || ctx.Value(xraySelectedTCPExecutionKey{}) != e || p.cleanup == nil || p.scope == nil || p.scope.manager != p.manager {
		return ErrXrayOperationOwner
	}
	e.mu.Lock()
	unused := e.resource == nil && !e.started && !e.retired
	e.mu.Unlock()
	p.scope.mu.Lock()
	unused = unused && p.scope.open && len(p.scope.xraySelectedTCP) == 0 && p.scope.resourceCount() == 0 && len(p.scope.execution.Resources) == 0
	p.scope.mu.Unlock()
	if !unused {
		return ErrXrayOperationOwner
	}
	return p.cleanup.WithCurrent(ctx, func() error {
		return e.material.control.CurrentForCleanupOperation(ctx, p.cleanup)
	})
}

func (p *xraySelectedTCPReplacement) withExecution(ctx context.Context, execution *xraySelectedTCPExecution, read func(context.Context) error) error {
	if p == nil || p.self != p || p.closed.Load() || p.manager == nil || p.prior == nil || p.prior.execution == nil || read == nil || execution == nil || execution.self != execution ||
		(execution != p.prior.execution && execution != p.candidate) || xraySelectedTCPFinite(ctx) != nil {
		return ErrXrayOperationOwner
	}
	if execution == p.prior.execution {
		c, end, err := p.priorContext(ctx)
		if err != nil {
			return err
		}
		defer end()
		return read(c)
	}
	if p.committed.Load() {
		o := p.manager.retainedXrayOwner()
		if o == nil || o.self != o || o.execution != execution {
			return ErrXrayOperationOwner
		}
		c, end, err := o.operation(ctx, p.cleanup, false)
		if err != nil {
			return err
		}
		defer end()
		return read(c)
	}
	c := context.WithValue(ctx, xrayRetainedOperationKey{}, nil)
	c = context.WithValue(c, xraySelectedTCPExecutionKey{}, execution)
	c = context.WithValue(c, xrayOperationMaterialKey{}, execution.material)
	cleanup, _ := ctx.Value(xrayOperationCleanupKey{}).(bool)
	c = context.WithValue(c, xrayOperationCleanupKey{}, cleanup)
	if execution.resource == nil {
		return ErrXrayOperationOwner
	}
	c = context.WithValue(c, xrayOperationOwnerKey{}, execution.resource.owner)
	c = execution.resource.scope.contextWith(networkPolicyConsumerContext(c, execution.plan))
	return read(c)
}
