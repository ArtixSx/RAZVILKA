package dataplane

import (
	"context"
	"errors"
	"os"
	"sync"

	"github.com/ArtixSx/razvilka/internal/operationgate"
)

// This one-use composition acquires the SAME COMMON writer before the original
// PreparedActive transition. PreparedActive still writes its separate resource
// journal: the witness proves only that COMMON publication/Add never began.
// The temporary marker permits comparison of this exact held lock, not effects.
type nfqwsActivePreparedPolicy struct {
	self        *nfqwsActivePreparedPolicy
	mu          sync.RWMutex
	used, open  bool
	parent      context.Context
	execution   *nfqws2ActiveExecution
	material    *NFQWSActiveMaterial
	resource    *NFQWSExecutionResource
	scope       *executionResourceScope
	binding     *NFQWSScopedBinding
	network     *nfqwsScopedNetworkBinding
	toolRunner  NFQWS2Runner
	baseRunner  NFQWS2Runner
	toolReview  string
	plan        *NFQWSScopedPlan
	prepared    *NFQWSPreparedHandle
	owner       *nfqws2ActiveOwner
	control     *operationgate.ControlEpochReview
	guards      *nfqwsExecutionTransferGuards
	observation NFQWSActiveObservation
	root, hash  string
	custody     *nfqwsPolicyRecovery
}

type nfqwsActivePreparedPolicyKey struct{}

func newNFQWSActivePreparedPolicy(ctx context.Context, e *nfqws2ActiveExecution, p *NFQWSPreparedHandle, binding NFQWSExecutionBinding, observation NFQWSActiveObservation) (*nfqwsActivePreparedPolicy, error) {
	if ctx == nil || e == nil || e.material == nil || e.resource == nil || e.resource.Plan() == nil || e.resource.Binding() != binding || observation.Binding != binding {
		return nil, ErrNFQWSScopedOwner
	}
	s := &nfqwsActivePreparedPolicy{parent: ctx, execution: e, material: e.material, resource: e.resource, scope: e.resource.scope,
		binding: e.binding, plan: e.resource.Plan(), prepared: p, control: e.material.control, guards: e.resource.transferGuards,
		observation: observation, root: e.resource.Root(), toolRunner: e.inventory.reader.Runner, baseRunner: e.runtimeFrozen.Runner, toolReview: e.inventory.review}
	if e.binding != nil {
		s.network = e.binding.network
	}
	s.self = s
	if p != nil {
		s.owner = p.owner
	}
	plan, err := s.plan.Effects()
	if err != nil {
		return nil, err
	}
	s.hash, err = PolicyEffectPlanDigest(plan)
	if err != nil {
		return nil, err
	}
	if err := s.associations(); err != nil || nfqws2ActiveOperation(ctx) != nil || ctx.Value(nfqws2ActivePreparedKey{}) != p || ctx.Value(nfqwsActivePreparedPolicyKey{}) != nil || ctx.Value(policyEffectReceiptBorrowKey{}) != nil {
		return nil, errors.Join(ErrNFQWSScopedOwner, err)
	}
	return s, nil
}

func (s *nfqwsActivePreparedPolicy) associations() error {
	if s == nil || s.self != s || s.parent == nil || s.execution == nil || s.execution.self != s.execution || s.material == nil ||
		s.execution.material != s.material || s.material.self != s.material || s.material.control != s.control || s.control == nil ||
		s.resource == nil || s.execution.resource != s.resource || s.resource.scope != s.scope || s.scope == nil ||
		s.binding == nil || s.execution.binding != s.binding || s.resource.Plan() != s.plan || s.plan == nil || s.resource.Root() != s.root ||
		s.binding.network != s.network || s.network == nil || s.execution.inventory.review != s.toolReview ||
		!sameNetworkPolicyDependency(s.execution.inventory.reader.Runner, s.toolRunner) || !sameNetworkPolicyDependency(s.execution.runtimeFrozen.Runner, s.baseRunner) ||
		s.prepared == nil || s.owner == nil || s.prepared.owner != s.owner || s.execution.prepared != s.prepared || s.resource.preparedOwner != s.prepared ||
		s.resource.transferGuards != s.guards || s.guards == nil || s.guards.control != s.control ||
		s.prepared.owner.admission.Binding != s.resource.Binding() || s.observation.Binding != s.resource.Binding() {
		return ErrNFQWSScopedOwner
	}
	e, err := s.binding.activeReadbackOwner(s.parent, s.plan)
	if err != nil || e != s.execution {
		return errors.Join(ErrNFQWSScopedOwner, err)
	}
	plan, err := s.plan.Effects()
	if err != nil {
		return err
	}
	digest, err := PolicyEffectPlanDigest(plan)
	if err != nil || digest != s.hash {
		return errors.Join(ErrNFQWSScopedOwner, err)
	}
	return nil
}

// c.mu is already held by the original Apply. No execution/resource lock spans
// PreparedActive here. Its original callbacks take only their existing locks;
// borrowed receipt reads take borrow.mu, never the recovery cursor mutex.
func (s *nfqwsActivePreparedPolicy) prepare(ctx context.Context, c *nfqwsPolicyRecovery) (result error) {
	if s == nil || ctx == nil || c == nil || c.preparedPolicy != s || c.execution != s.execution || !c.preLedgerArmed() || ctx.Value(policyEffectReceiptBorrowKey{}) != c.session.borrow || s.associations() != nil {
		return ErrPolicyAdditionUnknown
	}
	deadline, finite := ctx.Deadline()
	parentDeadline, parentFinite := s.parent.Deadline()
	if !finite || !parentFinite || deadline.After(parentDeadline) || nfqws2ActiveOperation(ctx) != nil || ctx.Value(nfqws2ActiveExecutionKey{}) != s.execution || ctx.Value(nfqws2ActivePreparedKey{}) != s.prepared || ctx.Value(nfqwsActivePreparedPolicyKey{}) != nil {
		return ErrPolicyAdditionUnknown
	}
	s.mu.Lock()
	if s.used || s.open || s.custody != nil {
		s.mu.Unlock()
		return ErrPolicyAdditionUnknown
	}
	s.used, s.open, s.custody = true, true, c
	s.mu.Unlock()
	preparedBase, cancelPrepared := context.WithCancel(ctx)
	stopParent := context.AfterFunc(s.parent, cancelPrepared)
	defer func() {
		stopParent()
		cancelPrepared()
		// Join even an escaping pure absence read before later policy admission.
		s.mu.Lock()
		s.open = false
		s.mu.Unlock()
		result = errors.Join(result, s.associations(), networkPolicyChecksContextError(s.parent), ctx.Err())
		result = nfqwsExecutionFailure("prepared.active", result)
	}()
	// Keep the actual caller's cancellation/deadline and SAME original borrow.
	// Only restore PreparedActive's prior consumer-plan value; this composition
	// added the policy Apply plan after the original prepared context was made.
	prepared := context.WithValue(preparedBase, networkPolicyConsumerPlanKey{}, s.parent.Value(networkPolicyConsumerPlanKey{}))
	prepared = context.WithValue(prepared, nfqwsActivePreparedPolicyKey{}, s)
	defer measureNFQWSActivePhase(s.execution, nfqwsProbePhasePrepared)()
	return s.resource.PreparedActive(prepared, s.resource.Binding(), s.observation)
}

// A present invalid marker never falls back to generic absent-lock admission.
// Only the actual original PreparedActive callback may use a held writer.
func nfqwsPreparedHeldAbsence(ctx context.Context, b *NFQWSScopedBinding, p *NFQWSScopedPlan, path string) (bool, error) {
	if ctx == nil {
		return false, nil
	}
	raw := ctx.Value(nfqwsActivePreparedPolicyKey{})
	if raw == nil {
		return false, nil
	}
	s, ok := raw.(*nfqwsActivePreparedPolicy)
	if !ok || s == nil || s.self != s || s.parent == nil {
		return true, ErrNFQWSScopedOwner
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	c := s.custody
	deadline, finite := ctx.Deadline()
	parentDeadline, parentFinite := s.parent.Deadline()
	if !s.open || !s.used || c == nil || c.preparedPolicy != s || c.execution != s.execution || !c.preLedgerArmed() ||
		!finite || !parentFinite || deadline.After(parentDeadline) || ctx.Err() != nil || s.parent.Err() != nil ||
		ctx.Value(nfqws2ActiveExecutionKey{}) != s.execution || ctx.Value(nfqws2ActivePreparedKey{}) != s.prepared ||
		ctx.Value(policyEffectReceiptBorrowKey{}) != c.session.borrow || p != s.plan || path != s.root || c.session.hash != s.hash ||
		s.associations() != nil {
		return true, ErrNFQWSScopedOwner
	}
	// VerifyPrepared intentionally uses an original read-only binding copy;
	// validate its original network/runner/tool/owner associations as well.
	e, err := b.activeReadbackOwner(ctx, p)
	if err != nil || e != s.execution {
		return true, errors.Join(ErrNFQWSScopedOwner, err)
	}
	borrow := c.session.borrow
	borrow.mu.Lock()
	defer borrow.mu.Unlock()
	if !borrow.absent || borrow.published != nil || borrow.currentOwner() != nil {
		return true, ErrPolicyAdditionUnknown
	}
	if _, err := c.session.root.LstatChild(policyAdditionFile); !errors.Is(err, os.ErrNotExist) {
		return true, errors.Join(ErrPolicyAdditionUnknown, err)
	}
	return true, errors.Join(borrow.currentOwner(), ctx.Err(), s.parent.Err())
}

// Existing private writer fault seam, after the original fresh absence proof
// released BOTH locks. Ordinary options have no hook. A native failure here
// occurs inside PreparedActive before capture-ready, without bypassing a read.
func nfqwsPreparedAbsenceFault(ctx context.Context) error {
	if ctx == nil || ctx.Err() != nil {
		return ErrNFQWSScopedOwner
	}
	s, ok := ctx.Value(nfqwsActivePreparedPolicyKey{}).(*nfqwsActivePreparedPolicy)
	if !ok || s == nil || s.self != s {
		return ErrNFQWSScopedOwner
	}
	s.mu.RLock()
	c := s.custody
	valid := s.open && s.used && c != nil && c.preparedPolicy == s && c.session != nil && ctx.Value(policyEffectReceiptBorrowKey{}) == c.session.borrow
	var session *policyEffectSession
	if valid {
		session = c.session
	}
	s.mu.RUnlock()
	if !valid {
		return ErrPolicyAdditionUnknown
	}
	return session.fault("nfq-original-prepared-absence", -1)
}
