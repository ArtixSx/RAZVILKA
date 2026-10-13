package app

import (
	"context"
	"errors"
	"net/netip"
	"reflect"
	"sync"
	"sync/atomic"

	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/operationgate"
	"github.com/ArtixSx/razvilka/internal/physicalscope"
	"github.com/ArtixSx/razvilka/internal/startuptools"
)

// This concrete App owner is the only Xray branch of the shared policy
// dispatcher. Factory/control, original operation and actual resource issuers
// remain independent; a copied object or context tag grants no command.
type ManagedXraySelectedTCPListRuntime struct {
	self                                *ManagedXraySelectedTCPListRuntime
	mu                                  sync.Mutex
	app                                 *App
	manager                             *dataplane.Manager
	policy                              *managedListPolicyOwner
	adapter                             *dataplane.ProxyTunnelAdapter
	preparing, active, pending, stopped *managedXraySelectedTCPListExecution
	closed                              bool
	closeErr                            error
}

type managedXraySelectedTCPListExecution struct {
	self                                  *managedXraySelectedTCPListExecution
	runtime                               *ManagedXraySelectedTCPListRuntime
	scope                                 *ListScopeBinding
	finiteScope                           *xrayFiniteScopeBinding
	source                                *XrayListRuntimeSource
	preparation                           *listXrayRuntimePreparation
	material                              *dataplane.XrayOperationMaterial
	plan                                  dataplane.Plan
	listener                              netip.AddrPort
	primary                               *physicalscope.PrimaryIPv4Review
	finitePrimary                         *physicalscope.FiniteIPv4PrimaryReview
	lanAdmission                          *dataplane.LANPolicyCommandAdmission
	terminal                              *dataplane.XraySelectedTCPTerminal
	pendingContext                        context.Context
	pendingStop                           bool
	stopBefore, stopCommitted             *config.Config
	pendingCloseOperation, pendingRelease func()
	previous                              *managedXraySelectedTCPListExecution
	pendingReplacementComplete            bool
	stopCompletion                        *managedXrayStopCompletion
}

type managedXraySelectedTCPListOperation struct {
	self      *managedXraySelectedTCPListOperation
	execution *managedXraySelectedTCPListExecution
	prior     *managedXraySelectedTCPListExecution
	cleanup   *operationgate.ExclusiveCleanupReview
	open      atomic.Bool
}
type managedXraySelectedTCPListOperationKey struct{}

func (r *ManagedXraySelectedTCPListRuntime) original() bool {
	return r != nil && r.self == r && !r.closed && r.app != nil && r.app.Dataplane == r.manager &&
		r.app.managedXraySelectedTCPList == r && r.policy != nil && r.policy.self == r.policy && r.policy.app == r.app && r.policy.manager == r.manager
}

func (r *ManagedXraySelectedTCPListRuntime) executionFor(ctx context.Context) (*managedXraySelectedTCPListExecution, *managedXraySelectedTCPListOperation, error) {
	if !r.original() || xrayListSourceContext(ctx) != nil {
		return nil, nil, ErrXrayListSource
	}
	o, ok := ctx.Value(managedXraySelectedTCPListOperationKey{}).(*managedXraySelectedTCPListOperation)
	if !ok || o == nil || o.self != o || !o.open.Load() || o.cleanup == nil || o.execution == nil || o.execution.self != o.execution || o.execution.runtime != r {
		return nil, nil, ErrXrayListSource
	}
	e := o.execution
	if o.prior != nil && o.prior.self == o.prior && o.execution.previous == o.prior && o.prior.material != nil && o.prior.material.IsCleanupContext(ctx) {
		e = o.prior
	}
	if r.preparing != e && r.pending != e && r.active != e && r.stopped != e {
		if e != o.prior || (r.preparing != o.execution && r.pending != o.execution && r.active != o.execution) {
			return nil, nil, ErrXrayListSource
		}
	}
	return e, o, nil
}

func (r *ManagedXraySelectedTCPListRuntime) operation(ctx context.Context, e *managedXraySelectedTCPListExecution, cleanup *operationgate.ExclusiveCleanupReview) (context.Context, func(), error) {
	if !r.original() || xrayListSourceContext(ctx) != nil || e == nil || e.self != e || e.runtime != r || cleanup == nil {
		return nil, nil, ErrXrayListSource
	}
	o := &managedXraySelectedTCPListOperation{execution: e, prior: e.previous, cleanup: cleanup}
	o.self = o
	o.open.Store(true)
	ctx = context.WithValue(ctx, managedXraySelectedTCPListOperationKey{}, o)
	ctx = dataplane.WithWGInactivityCleanup(ctx, cleanup)
	ctx = startuptools.WithCommandAdmission(ctx, r)
	return ctx, func() { o.open.Store(false) }, nil
}

func (e *managedXraySelectedTCPListExecution) guard(ctx context.Context) error {
	r := e.runtime
	if _, _, err := r.executionFor(ctx); err != nil {
		return err
	}
	if e.source == nil || !e.scopeOwner().matches(r.app, r.app.Store) || e.material == nil {
		return ErrXrayListSource
	}
	if e.material.IsCleanupContext(ctx) {
		return r.lanCleanupGuard(ctx, e.plan.LAN, dataplane.LANPolicyEffect{})
	}
	if e.material.RetainedOperationContext(ctx) {
		return e.committedGuard(ctx, e.plan)
	}
	return r.app.Operations.WithExclusiveContext(ctx, func() error {
		if err := e.source.Current(ctx); err != nil {
			return err
		}
		if err := e.scopeOwner().ScopeCheck(ctx, e.plan.LAN); err != nil {
			return err
		}
		return e.source.Current(ctx)
	})
}

func (e *managedXraySelectedTCPListExecution) committedGuard(ctx context.Context, plan dataplane.Plan) error {
	r := e.runtime
	if _, _, err := r.executionFor(ctx); err != nil {
		return err
	}
	if e.source == nil || !e.scopeOwner().matches(r.app, r.app.Store) || e.material == nil || plan.PlanID != e.plan.PlanID || plan.Digest != e.plan.Digest || plan.Revision != e.plan.Revision || !reflect.DeepEqual(plan.LAN, e.plan.LAN) {
		return ErrXrayListSource
	}
	return r.app.Operations.WithExclusiveContext(ctx, func() error {
		if err := r.policy.control.Current(ctx); err != nil {
			return err
		}
		s := e.source
		s.mu.Lock()
		defer s.mu.Unlock()
		if s.closed.Load() || s.invalid || s.commitOwnersCurrent() != nil || !reflect.DeepEqual(s.store.Get(), s.expected) {
			return ErrXrayListSource
		}
		if err := s.currentDestinations(ctx); err != nil {
			return err
		}
		wan, err := r.app.freshNetworkProfile(ctx)
		if err != nil || wan != s.wan {
			return errors.Join(ErrXrayListSource, err)
		}
		if err := e.scopeOwner().cleanupScopeCheck(ctx, plan.LAN); err != nil {
			return err
		}
		if err := e.primaryCurrentRetained(ctx); err != nil {
			return err
		}
		return errors.Join(s.registration.Current(ctx), s.currentDestinations(ctx))
	})
}

func (e *managedXraySelectedTCPListExecution) cleanupGuard(ctx context.Context, plan dataplane.Plan) error {
	if plan.PlanID != e.plan.PlanID || plan.Digest != e.plan.Digest || !reflect.DeepEqual(plan.LAN, e.plan.LAN) {
		return ErrXrayListSource
	}
	return e.runtime.lanCleanupGuard(ctx, plan.LAN, dataplane.LANPolicyEffect{})
}

func (r *ManagedXraySelectedTCPListRuntime) scopeCheck(ctx context.Context, plan *dataplane.LANPolicyRuntimePlan) error {
	e, _, err := r.executionFor(ctx)
	if err != nil || !e.scopeOwner().matches(r.app, r.app.Store) || !reflect.DeepEqual(plan, e.plan.LAN) {
		return errors.Join(ErrListScopeChanged, err)
	}
	if e.material != nil && e.material.IsCleanupContext(ctx) {
		return r.lanCleanupGuard(ctx, plan, dataplane.LANPolicyEffect{})
	}
	if e.material != nil && e.material.RetainedOperationContext(ctx) {
		return e.committedGuard(ctx, e.plan)
	}
	return e.scopeOwner().ScopeCheck(ctx, plan)
}

func (r *ManagedXraySelectedTCPListRuntime) lanApplyGuard(ctx context.Context, plan *dataplane.LANPolicyRuntimePlan, _ dataplane.LANPolicyEffect) error {
	e, _, err := r.executionFor(ctx)
	if err != nil || !reflect.DeepEqual(plan, e.plan.LAN) {
		return errors.Join(ErrListScopeChanged, err)
	}
	return e.guard(ctx)
}

func (r *ManagedXraySelectedTCPListRuntime) lanCleanupGuard(ctx context.Context, plan *dataplane.LANPolicyRuntimePlan, _ dataplane.LANPolicyEffect) error {
	e, o, err := r.executionFor(ctx)
	if err != nil || !e.scopeOwner().matches(r.app, r.app.Store) || !reflect.DeepEqual(plan, e.plan.LAN) {
		return errors.Join(ErrListScopeChanged, err)
	}
	return o.cleanup.WithCurrent(ctx, func() error {
		if err := r.policy.control.CurrentForCleanupOperation(ctx, o.cleanup); err != nil {
			return err
		}
		return e.scopeOwner().cleanupScopeCheck(ctx, plan)
	})
}

func (r *ManagedXraySelectedTCPListRuntime) WithStart(ctx context.Context, name string, args []string, digest string, begin func() error) error {
	e, _, err := r.executionFor(ctx)
	if err != nil {
		return err
	}
	if e.lanAdmission == nil {
		return ErrXrayListSource
	}
	if handled, err := dataplane.WithLANPolicyCommandStart(ctx, name, args, digest, begin); handled {
		return err
	}
	return dataplane.WithXraySelectedTCPCommandStart(ctx, name, args, digest, begin)
}
