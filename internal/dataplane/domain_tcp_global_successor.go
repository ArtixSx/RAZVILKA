package dataplane

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"sync"
	"sync/atomic"

	"github.com/ArtixSx/razvilka/internal/dnscontrol"
	"github.com/ArtixSx/razvilka/internal/ownedfs"
	"github.com/ArtixSx/razvilka/internal/updatecheck"
)

// One original writer link, reserved BEFORE replacing latest. Its records are
// subsequently borrowed by the actual Xray resource; no pathname can recreate
// either holder. Unknown publication retains this cursor and all prior FDs.
type domainTCPGlobalSuccessor struct {
	self           *domainTCPGlobalSuccessor
	mu             sync.Mutex
	pool           *domainTCPStandbyPool
	scope          *executionResourceScope
	records        *xraySelectedTCPExecutionRecords
	admission      *domainTCPContinuationAdmission
	previous       *domainTCPGlobalHistory
	previousKeeper *domainTCPGlobalKeeper
	terminal       *domainTCPInitialRetirement
	definition     ExecutionDomainDNSCoexistenceDefinition
	request        context.Context // SAME still-live request may retry a pre-action ACK.
	actionStarted  bool
	pending        bool
	globalAccepted bool
	sealed         bool
	failure        error
	initialFault   func(string) error // Error-only, configured on the SAME detached prior before construction.
	continuation   *dnscontrol.SyntheticDNSLedgerContinuation
	listener       atomic.Pointer[domainTCPPoolListenerWitness]
	history        *updatecheck.ExecutionHistoryAdmission
	failedCustody  atomic.Bool
	cleanup        *domainTCPFailureCleanup // Serialized Manager cleanup; never a forward carrier.
	cleanupFault   func(string) error       // Private tagged error-only cut after actual cleanup ACK.
	cleanupIssued  atomic.Bool
}

func newDomainTCPGlobalSuccessor(ctx context.Context, pool *domainTCPStandbyPool, s *executionResourceScope, admission *domainTCPContinuationAdmission) (*domainTCPGlobalSuccessor, error) {
	if pool == nil || pool.self != pool || s == nil || s.manager != pool.manager || !s.domainTCPProof || s.execution == nil || s.domainSuccessor != nil || s.networkIdentity == nil || s.owned == nil || s.anchor == nil || validateDomainTCPProofPlan(s.plan) != nil || admission == nil {
		return nil, ErrPolicyAdditionUnknown
	}
	entries, err := pool.originals()
	if err != nil {
		return nil, err
	}
	if err := admission.initial(ctx, pool.manager, s.plan, entries[len(entries)-1].detached); err != nil {
		return nil, err
	}
	pool.mu.Lock()
	keeper := pool.keeper
	pool.mu.Unlock()
	previous := entries[len(entries)-1].history
	if keeper != nil {
		previous, err = borrowDomainTCPKeeperHistory(ctx, keeper)
		if err != nil {
			return nil, err
		}
	}
	d := ExecutionDomainDNSCoexistenceDefinition{Schema: 1, NewPlanID: s.plan.PlanID, NewPlanDigest: s.plan.Digest, NewDomainDigest: s.plan.DomainPolicy.Digest, NewDefinition: s.plan.SyntheticDNS.Definition, NewNetworkIdentity: s.networkIdentity.value}
	for i, entry := range entries {
		if err := entry.current(ctx, pool.manager, s.plan, keeper != nil || i != len(entries)-1); err != nil {
			return nil, err
		}
		d.Prior = append(d.Prior, entry.definition)
	}
	d = d.Clone()
	if err := d.validateExecution(*s.execution); err != nil {
		return nil, err
	}
	records, err := newXraySelectedTCPRecords(s)
	if err != nil {
		return nil, err
	}
	scopeInfo, scopeErr := s.owned.RootInfo()
	recordInfo, recordErr := records.transactionRoot.RootInfo()
	if scopeErr != nil || recordErr != nil || !networkPolicyPrivateDirectory(scopeInfo) || !networkPolicyPrivateDirectory(recordInfo) || !os.SameFile(s.anchor, scopeInfo) || !os.SameFile(records.transactionAnchor, recordInfo) || !os.SameFile(scopeInfo, recordInfo) {
		return nil, errors.Join(ErrPolicyAdditionUnknown, scopeErr, recordErr, records.close())
	}
	c := &domainTCPGlobalSuccessor{pool: pool, scope: s, records: records, admission: admission, previous: previous, previousKeeper: keeper, definition: d, request: ctx, pending: true}
	prior := entries[len(entries)-1].detached
	prior.mu.Lock()
	c.initialFault = prior.initialFault
	c.continuation = prior.continuation
	prior.mu.Unlock()
	if keeper != nil {
		c.continuation = keeper.continuation
	}
	c.self = c
	c.history = admission.history
	pool.manager.retainedXrayMu.Lock()
	pool.mu.Lock()
	priorCursor := pool.successor
	validPrior := keeper == nil && pool.manager.retainedXray == entries[len(entries)-1].retained && (priorCursor == nil || priorCursor.self == priorCursor && priorCursor.scope == entries[len(entries)-1].retained.scope && priorCursor.forwardCurrentState() == nil)
	if keeper != nil {
		validPrior = pool.keeper == keeper && keeper.ready.Load() && !keeper.closed.Load() && priorCursor == keeper.cursor && pool.manager.retainedXray == nil
	}
	if pool.manager.domainPool != pool || !validPrior {
		pool.mu.Unlock()
		pool.manager.retainedXrayMu.Unlock()
		return nil, errors.Join(ErrPolicyAdditionUnknown, records.close())
	}
	pool.successor = c
	pool.manager.retainedXray = nil
	pool.mu.Unlock()
	pool.manager.retainedXrayMu.Unlock()
	s.domainSuccessor = c
	admission.cursor = c
	marker := d.Clone()
	s.execution.DomainDNSCoexistence = &marker
	return c, nil
}

func (c *domainTCPGlobalSuccessor) original() error {
	if c == nil || c.self != c || c.pool == nil || c.scope == nil || c.records == nil || c.records.scope != c.scope || c.scope.domainSuccessor != c || c.scope.manager != c.pool.manager {
		return ErrPolicyAdditionUnknown
	}
	c.pool.mu.Lock()
	same := c.pool.self == c.pool && c.pool.successor == c
	c.pool.mu.Unlock()
	if !same {
		return ErrPolicyAdditionUnknown
	}
	return nil
}

func (c *domainTCPGlobalSuccessor) comparePrior(ctx context.Context, after bool) error {
	return c.comparePriorWithSuccessorRead(ctx, after, nil)
}
func (c *domainTCPGlobalSuccessor) comparePriorWithSuccessorRead(ctx context.Context, after bool, read *domainTCPSuccessorRead) error {
	if err := c.original(); err != nil {
		return err
	}
	entries, err := c.pool.originals()
	if err != nil {
		return err
	}
	for i, entry := range entries {
		if err := entry.currentWithSuccessorRead(ctx, c.pool.manager, c.scope.plan, c.previousKeeper != nil || after || i != len(entries)-1, read); err != nil {
			return err
		}
	}
	return nil
}

func (c *domainTCPGlobalSuccessor) forwardCurrent() error {
	if err := c.original(); err != nil {
		return err
	}
	return c.forwardCurrentState()
}

// State only; caller holding pool.mu must not recursively compare the pool.
func (c *domainTCPGlobalSuccessor) forwardCurrentState() error {
	if c == nil || c.self != c {
		return ErrPolicyAdditionUnknown
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.pending || c.failure != nil || c.failedCustody.Load() || !c.globalAccepted || !c.sealed {
		return errors.Join(ErrPolicyAdditionUnknown, c.failure)
	}
	return nil
}

// Only the exact still-live original request can retry a failed initial
// publication before action/resource issuance. A new request, cleanup token,
// saved marker or matching plan cannot mint another forward opportunity.
func (m *Manager) originalDomainPublicationRetry(ctx context.Context, plan Plan, prior *DomainTCPDetachedStandby) (*domainTCPGlobalSuccessor, error) {
	m.retainedXrayMu.Lock()
	pool := m.domainPool
	m.retainedXrayMu.Unlock()
	if pool == nil {
		return nil, nil
	}
	pool.mu.Lock()
	c := pool.successor
	pool.mu.Unlock()
	if c == nil {
		return nil, nil
	}
	c.mu.Lock()
	pending, started := c.pending, c.actionStarted
	c.mu.Unlock()
	if !pending {
		return nil, nil
	}
	entries, err := pool.originals()
	if err != nil {
		return nil, err
	}
	if !sameNetworkPolicyDependency(c.request, ctx) || ctx.Err() != nil || started || c.original() != nil || len(entries) == 0 || entries[len(entries)-1].detached != prior || !xraySelectedTCPSamePlan(c.scope.plan, plan) {
		return nil, ErrPolicyAdditionUnknown
	}
	c.scope.mu.Lock()
	beforeAction := len(c.scope.execution.Resources) == 0 && c.scope.execution.State == "checking" && c.scope.domainTCPOwner == nil && c.scope.open && c.scope.observationOpen.Load()
	c.scope.mu.Unlock()
	if !beforeAction {
		return nil, ErrPolicyAdditionUnknown
	}
	return c, nil
}

// Caller holds the original serialized Manager operation (and may hold the
// new scope metadata mutex). Never reenter that scope's mutex from this leaf.
func (c *domainTCPGlobalSuccessor) publish(ctx context.Context, data []byte) error {
	return c.publishFrame(ctx, data, nil)
}

// Cleanup frames require the SAME active original cursor. Initial retirement
// has no issued resources; failed-action cleanup retains only its originals.
// Neither metadata carrier grants Start, flow, DNS send or removal authority.
func (c *domainTCPGlobalSuccessor) publishFrame(ctx context.Context, data []byte, retirement *domainTCPInitialRetirement) error {
	if err := c.original(); err != nil {
		return err
	}
	if xraySelectedTCPFinite(ctx) != nil {
		return ErrPolicyAdditionUnknown
	}
	c.mu.Lock()
	var admissionErr error
	var cleanupCut *domainTCPFailureCleanup
	if retirement == nil {
		if raw := ctx.Value(domainTCPFailureCleanupKey{}); raw != nil {
			cleanup, ok := raw.(*domainTCPFailureCleanup)
			if !ok || cleanup == nil || cleanup.cursor != c {
				admissionErr = ErrPolicyAdditionUnknown
			} else {
				admissionErr = cleanup.local(ctx, cleanup.resource)
				if admissionErr == nil {
					cleanupCut = cleanup
				}
			}
		} else {
			admissionErr = c.admission.current(c, ctx)
		}
	} else {
		admissionErr = retirement.local(c, ctx)
		if admissionErr == nil && (!bytes.Equal(data, retirement.image) || c.actionStarted || len(c.scope.execution.Resources) != 0 || c.scope.execution.State != "temporary-complete") {
			admissionErr = ErrPolicyAdditionUnknown
		}
	}
	if admissionErr != nil {
		c.mu.Unlock()
		return admissionErr
	}
	failure, sealed, accepted, started := c.failure, c.sealed, c.globalAccepted, c.actionStarted
	c.pending = true
	c.mu.Unlock()
	if failure != nil {
		return failure
	}
	expected, marshalErr := json.Marshal(c.scope.execution)
	if marshalErr != nil || !bytes.Equal(expected, data) {
		return errors.Join(ErrExecutionJournal, marshalErr)
	}
	if accepted && !sealed {
		// The prior attempt already transferred the actual authored global FD.
		// Recover its original rename bookend BEFORE asking the old FD to have
		// its former name. A reopened/equal-byte file cannot enter this path.
		if err := c.sealAcceptedGlobal(ctx); err != nil {
			return err
		}
		sealed = true
	}
	var execution Execution
	if json.Unmarshal(data, &execution) != nil || execution.DomainDNSCoexistence == nil || execution.DomainDNSCoexistence.validateExecution(execution) != nil {
		return ErrExecutionJournal
	}
	wanted, err := json.Marshal(c.definition)
	actual, e2 := json.Marshal(execution.DomainDNSCoexistence)
	if err != nil || e2 != nil || !bytes.Equal(wanted, actual) {
		return ErrExecutionJournal
	}
	if err := c.comparePrior(ctx, sealed); err != nil {
		return err
	}
	if err := c.records.beforePublication(); err != nil {
		return err
	}
	if err := c.records.publishOriginalDurable(0, data, syncDataplaneJournalDirectory); err != nil {
		return err
	}
	if retirement == nil && c.initialFault != nil && !started {
		if err := c.initialFault("transaction"); err != nil {
			return err
		}
	}
	if err := c.comparePrior(ctx, sealed); err != nil {
		return err
	}
	if cleanupCut != nil && cleanupCut.fault != nil {
		if err := cleanupCut.local(ctx, cleanupCut.resource); err != nil {
			return err
		}
		if err := cleanupCut.fault(cleanupCut.imageStage + "-transaction"); err != nil {
			return err
		}
	}
	// Capture always precedes the directory ACK. Once the old global loses its
	// name, only the exact original cursor may seal the observed transition.
	err = c.records.publishOriginalDurable(1, data, func(root *ownedfs.Root) error {
		c.mu.Lock()
		c.globalAccepted = true
		c.mu.Unlock()
		if !sealed {
			return c.sealAcceptedGlobal(ctx)
		}
		return syncDataplaneJournalDirectory(root)
	})
	if err != nil {
		return err
	}
	if retirement == nil && c.initialFault != nil && !started {
		if err := c.initialFault("global"); err != nil {
			return err
		}
	}
	if err := c.records.current(ctx, true); err != nil {
		return err
	}
	if err := c.comparePrior(ctx, true); err != nil {
		return err
	}
	if c.previousKeeper != nil {
		if err := c.previousKeeper.closeForSuccessor(ctx, c); err != nil {
			return err
		}
	}
	if retirement == nil && ctx.Value(domainTCPFailureCleanupKey{}) == nil {
		c.mu.Lock()
		c.pending = false
		c.mu.Unlock()
	}
	return nil
}

// This leaf can prove only a SAME authored file transition, not an old
// standby/native owner. publish independently brackets it with all originals.
// Capture precedes every error, so retry never reopens/adopts the new name.
func (c *domainTCPGlobalSuccessor) sealAcceptedGlobal(ctx context.Context) error {
	if err := c.original(); err != nil {
		return err
	}
	c.mu.Lock()
	accepted, sealed := c.globalAccepted, c.sealed
	c.mu.Unlock()
	if !accepted {
		return ErrPolicyAdditionUnknown
	}
	if err := c.records.current(ctx, true); err != nil {
		return err
	}
	last := c.previous
	if last == nil {
		return ErrPolicyAdditionUnknown
	}
	if !sealed {
		c.records.mu.Lock()
		file := c.records.files[1]
		c.records.mu.Unlock()
		if err := last.sealOriginalRename(ctx, file); err != nil {
			return err
		}
		c.mu.Lock()
		c.sealed = true
		c.mu.Unlock()
	} else if err := last.currentHistorical(ctx); err != nil {
		return err
	}
	if err := syncDataplaneJournalDirectory(c.records.root); err != nil {
		return err
	}
	return c.records.current(ctx, true)
}
