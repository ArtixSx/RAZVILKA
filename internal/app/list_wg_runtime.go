package app

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"reflect"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/operationgate"
	"github.com/ArtixSx/razvilka/internal/startuptools"
)

type ManagedWGListRuntime struct {
	self                                *ManagedWGListRuntime
	mu                                  sync.Mutex
	app                                 *App
	manager                             *dataplane.Manager
	policy                              *managedListPolicyOwner
	preparing, active, pending, stopped *managedWGListExecution
	closed                              bool
}
type managedWGListExecution struct {
	self                                  *managedWGListExecution
	runtime                               *ManagedWGListRuntime
	scope                                 *ListScopeBinding
	source                                *WGListRuntimeSource
	preparation                           *WGListRuntimePreparation
	plan                                  dataplane.Plan
	lanAdmission                          *dataplane.LANPolicyCommandAdmission
	terminal                              *dataplane.WGTerminal
	pendingContext                        context.Context
	pendingStop                           bool
	stopBefore, stopCommitted             *config.Config
	pendingCloseOperation, pendingRelease func()
}
type managedWGListOperation struct {
	self      *managedWGListOperation
	execution *managedWGListExecution
	cleanup   *operationgate.ExclusiveCleanupReview
	open      atomic.Bool
}
type managedWGListOperationKey struct{}

func (a *App) ConfigureReviewedStockWGList(ctx, panel context.Context) (*ManagedWGListRuntime, error) {
	if a == nil {
		return nil, dataplane.ErrWGOperationOwner
	}
	a.managedWGListMu.Lock()
	defer a.managedWGListMu.Unlock()
	if r := a.managedWGList; r != nil {
		if !r.original() || r.policy.panel != panel {
			return nil, dataplane.ErrWGOperationOwner
		}
		return r, nil
	}
	p, err := a.configureReviewedStockListPolicy(ctx, panel)
	if err != nil {
		return nil, err
	}
	r := &ManagedWGListRuntime{app: a, manager: p.manager, policy: p}
	r.self = r
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed.Load() || p.wg != nil {
		return nil, dataplane.ErrWGOperationOwner
	}
	a.managedWGList, p.wg = r, r
	return r, nil
}
func (r *ManagedWGListRuntime) original() bool {
	return r != nil && r.self == r && !r.closed && r.app != nil && r.app.managedWGList == r && r.app.Dataplane == r.manager && r.policy != nil && r.policy.original() && r.policy.wg == r
}
func (r *ManagedWGListRuntime) executionFor(ctx context.Context) (*managedWGListExecution, *managedWGListOperation, error) {
	if !r.original() || ctx == nil || ctx.Err() != nil {
		return nil, nil, dataplane.ErrWGOperationOwner
	}
	op, ok := ctx.Value(managedWGListOperationKey{}).(*managedWGListOperation)
	if !ok || op == nil || op.self != op || !op.open.Load() || op.cleanup == nil || op.execution == nil || op.execution.self != op.execution || op.execution.runtime != r {
		return nil, nil, dataplane.ErrWGOperationOwner
	}
	e := op.execution
	if r.preparing != e && r.active != e && r.pending != e && r.stopped != e {
		return nil, nil, dataplane.ErrWGOperationOwner
	}
	return e, op, nil
}
func (r *ManagedWGListRuntime) operation(ctx context.Context, e *managedWGListExecution, cleanup *operationgate.ExclusiveCleanupReview) (context.Context, func(), error) {
	if !r.original() || e == nil || e.self != e || e.runtime != r || cleanup == nil {
		return nil, nil, dataplane.ErrWGOperationOwner
	}
	op := &managedWGListOperation{execution: e, cleanup: cleanup}
	op.self = op
	op.open.Store(true)
	ctx = context.WithValue(ctx, managedWGListOperationKey{}, op)
	ctx = dataplane.WithWGInactivityCleanup(ctx, cleanup)
	return startuptools.WithCommandAdmission(ctx, r), func() { op.open.Store(false) }, nil
}
func (p *managedListPolicyOwner) wgRuntimeFor(ctx context.Context) (*ManagedWGListRuntime, error) {
	if ctx == nil {
		return nil, dataplane.ErrNetworkPolicyAuthority
	}
	if ctx.Value(managedWGListOperationKey{}) == nil {
		return nil, nil
	}
	if !p.original() || p.closed.Load() || p.wg == nil || p.wg.policy != p || ctx.Value(managedNFQWSListOperationKey{}) != nil || ctx.Value(managedXraySelectedTCPListOperationKey{}) != nil {
		return nil, dataplane.ErrNetworkPolicyAuthority
	}
	_, _, err := p.wg.executionFor(ctx)
	return p.wg, err
}
func (r *ManagedWGListRuntime) scopeCheck(ctx context.Context, lan *dataplane.LANPolicyRuntimePlan) error {
	e, _, err := r.executionFor(ctx)
	if err != nil || e.preparation == nil || !reflect.DeepEqual(lan, e.plan.LAN) {
		return errors.Join(dataplane.ErrWGOperationOwner, err)
	}
	m := e.preparation.binding.material
	if m.IsCleanupContext(ctx) {
		return r.lanCleanupGuard(ctx, lan, dataplane.LANPolicyEffect{})
	}
	if m.RetainedOperationContext(ctx) {
		return e.preparation.CurrentRetained(ctx)
	}
	return e.scope.ScopeCheck(ctx, lan)
}
func (r *ManagedWGListRuntime) lanApplyGuard(ctx context.Context, lan *dataplane.LANPolicyRuntimePlan, _ dataplane.LANPolicyEffect) error {
	e, _, err := r.executionFor(ctx)
	if err != nil || !reflect.DeepEqual(lan, e.plan.LAN) {
		return errors.Join(dataplane.ErrWGOperationOwner, err)
	}
	return e.preparation.guard(ctx)
}
func (r *ManagedWGListRuntime) lanCleanupGuard(ctx context.Context, lan *dataplane.LANPolicyRuntimePlan, _ dataplane.LANPolicyEffect) error {
	e, op, err := r.executionFor(ctx)
	if err != nil || e.scope == nil || !reflect.DeepEqual(lan, e.plan.LAN) {
		return errors.Join(dataplane.ErrWGOperationOwner, err)
	}
	return op.cleanup.WithCurrent(ctx, func() error {
		if err := r.policy.control.CurrentForCleanupOperation(ctx, op.cleanup); err != nil {
			return err
		}
		return e.scope.cleanupScopeCheck(ctx, lan)
	})
}
func (r *ManagedWGListRuntime) WithStart(ctx context.Context, name string, args []string, digest string, begin func() error) error {
	e, _, err := r.executionFor(ctx)
	if err != nil {
		return err
	}
	if e.lanAdmission == nil {
		return dataplane.ErrWGOperationOwner
	}
	if handled, err := dataplane.WithLANPolicyCommandStart(ctx, name, args, digest, begin); handled {
		return err
	}
	return dataplane.ErrWGOperationOwner // WG uses its private scope-issued Start carrier.
}
func (e *managedWGListExecution) prepare(ctx context.Context, serviceID string) error {
	r := e.runtime
	var err error
	e.scope, err = NewReviewedStockNC1812ListScopeBinding(ctx, r.app, r.policy.provider)
	if err != nil {
		return err
	}
	e.source, err = r.app.ReviewWGListRuntimeSource(ctx, e.scope, serviceID)
	if err != nil {
		return err
	}
	if !r.policy.wgAvailable[dataplane.AdapterID(e.source.resolved)] {
		return dataplane.ErrWGOperationOwner
	}
	e.preparation, err = e.source.Prepare(ctx)
	if err != nil {
		return err
	}
	input, err := e.preparation.Input(ctx)
	if err != nil {
		return err
	}
	plan, err := dataplane.BuildAt(input, time.Now().UTC())
	if err != nil || !plan.Ready {
		return errors.Join(ErrDefaultRouteCapability, err)
	}
	plan.Digest = defaultRouteDigest(struct{ Plan, Policy string }{plan.Digest, e.preparation.compilation.Digest()})
	var nonce [8]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return err
	}
	plan.PlanID = "dp-" + plan.Digest[:16] + "-" + hex.EncodeToString(nonce[:])
	e.plan = defaultRouteClonePlan(plan)
	e.preparation.execution = e
	return e.preparation.Current(ctx)
}
func (e *managedWGListExecution) close() error {
	if e == nil || e.self != e {
		return dataplane.ErrWGOperationOwner
	}
	if e.runtime != nil && e.runtime.manager != nil && e.runtime.manager.HasPendingManagedWG() {
		return dataplane.ErrWGOperationOwner
	}
	var err error
	if e.terminal != nil {
		if err := e.terminal.Close(); err != nil {
			return err
		}
	}
	if e.lanAdmission != nil {
		e.lanAdmission.Close()
	}
	if e.preparation != nil {
		err = errors.Join(err, e.preparation.Close())
	}
	if e.source != nil {
		err = errors.Join(err, e.source.Close())
	}
	if e.scope != nil {
		err = errors.Join(err, e.scope.Close())
	}
	return err
}
func (e *managedWGListExecution) applyReview(scope changeScope) applyReview {
	return applyReview{Revision: e.source.expected.Revision, Digest: applyReviewHash(struct {
		Kind, Config, Catalog, Compilation string
		Scope                              changeScope
	}{"managed-wg-literal", applyReviewHash(e.source.expected), e.source.catalog, e.preparation.compilation.Digest(), scope})}
}
func (r *ManagedWGListRuntime) Start(ctx context.Context, serviceID string) (dataplane.Execution, error) {
	return r.startReviewed(ctx, serviceID, changeScopeAll, nil)
}
func (r *ManagedWGListRuntime) startReviewed(ctx context.Context, serviceID string, scope changeScope, review *applyReview) (result dataplane.Execution, resultErr error) {
	if !r.original() {
		return result, dataplane.ErrWGOperationOwner
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.pending != nil || r.preparing != nil {
		return result, dataplane.ErrWGOperationOwner
	}
	if r.active != nil {
		if review == nil || serviceID != r.active.source.service {
			return result, dataplane.ErrWGOperationOwner
		}
		if err := r.currentLocked(ctx); err != nil {
			return result, err
		}
		if *review != r.active.applyReview(scope) {
			return result, dataplane.ErrReviewChanged
		}
		committed, found, err := r.manager.Committed()
		if err != nil || !found || !sameManagedWireGuardAppliedPlan(committed, r.active.plan) {
			return result, errors.Join(dataplane.ErrWGOperationOwner, err)
		}
		return dataplane.Execution{PlanID: committed.PlanID, Digest: committed.Digest, State: committed.State}, nil
	}
	if r.stopped != nil {
		if err := r.stopped.close(); err != nil {
			return result, err
		}
		r.stopped = nil
	}
	c, release, err := r.app.privateExclusiveOperation(ctx)
	if err != nil {
		return result, err
	}
	owned := true
	defer func() {
		if owned {
			release()
		}
	}()
	cfg := r.app.Store.Get()
	if cfg.ServiceControl.Stopped || cfg.SafeMode {
		return result, dataplane.ErrReviewChanged
	}
	if review != nil && review.Revision != cfg.Revision {
		return result, dataplane.ErrReviewChanged
	}
	e := &managedWGListExecution{runtime: r}
	e.self = e
	r.preparing = e
	keep := false
	defer func() {
		r.preparing = nil
		if !keep {
			resultErr = errors.Join(resultErr, e.close())
		}
	}()
	if err := e.prepare(c, serviceID); err != nil {
		return result, err
	}
	if review != nil && *review != e.applyReview(scope) {
		return result, dataplane.ErrReviewChanged
	}
	e.lanAdmission, err = r.manager.ReviewLANPolicyCommandAdmission(c, r.policy.gate, r.policy.inventory, r.policy.control)
	if err != nil {
		return result, err
	}
	cleanup, err := r.policy.control.ReviewExclusiveCleanup(c)
	if err != nil {
		return result, err
	}
	c, end, err := r.operation(c, e, cleanup)
	if err != nil {
		return result, err
	}
	defer func() {
		if owned {
			end()
		}
	}()
	c, err = e.preparation.OperationContext(c)
	if err != nil {
		return result, err
	}
	result, resultErr = r.app.applyDataplane(c, e.plan, func() (func() error, error) {
		if err := e.preparation.guard(c); err != nil {
			return nil, err
		}
		before := r.app.Store.Get()
		if !reflect.DeepEqual(before, cfg) {
			return nil, dataplane.ErrReviewChanged
		}
		started := time.Now()
		undo, err := r.app.Store.CommitNetworkPolicyWithRollback(before, e.preparation.compilation.Policy(), defaultRouteCloneServices(cfg.Services))
		finished := time.Now()
		if err != nil {
			return undo, err
		}
		if err := e.source.acceptWGCommitted(c, started, finished); err != nil {
			return undo, err
		}
		return undo, e.preparation.guard(c)
	})
	if resultErr != nil {
		if r.manager.HasPendingManagedWG() {
			e.pendingContext, e.pendingCloseOperation, e.pendingRelease = c, end, release
			r.pending = e
			keep, owned = true, false
			r.app.Operations.FenceJournal()
		}
		return result, resultErr
	}
	if result.State != "committed" {
		return result, dataplane.ErrWGOperationOwner
	}
	r.active = e
	keep = true
	return result, nil
}
func (r *ManagedWGListRuntime) Current(ctx context.Context) error {
	if !r.original() {
		return dataplane.ErrWGOperationOwner
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.currentLocked(ctx)
}
func (r *ManagedWGListRuntime) currentLocked(ctx context.Context) error {
	if r.active == nil || r.pending != nil {
		return dataplane.ErrWGOperationOwner
	}
	ctx, cancel := context.WithTimeout(ctx, 12*time.Second)
	defer cancel()
	c, release, err := r.app.privateExclusiveOperation(ctx)
	if err != nil {
		return err
	}
	defer release()
	cleanup, err := r.policy.control.ReviewExclusiveCleanup(c)
	if err != nil {
		return err
	}
	c, end, err := r.operation(c, r.active, cleanup)
	if err != nil {
		return err
	}
	defer end()
	return r.manager.CheckRetainedManagedWG(c)
}
func (r *ManagedWGListRuntime) review(ctx context.Context, serviceID string, scope changeScope) (plan dataplane.Plan, review applyReview, resultErr error) {
	if !r.original() {
		return plan, review, dataplane.ErrWGOperationOwner
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.pending != nil || r.preparing != nil {
		return plan, review, dataplane.ErrWGOperationOwner
	}
	if r.active != nil {
		if err := r.currentLocked(ctx); err != nil {
			return plan, review, err
		}
		plan = defaultRouteClonePlan(r.active.plan)
		plan.State, plan.Noop = "committed", true
		return plan, r.active.applyReview(scope), nil
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	c, release, err := r.app.privateExclusiveOperation(ctx)
	if err != nil {
		return plan, review, err
	}
	defer release()
	e := &managedWGListExecution{runtime: r}
	e.self = e
	r.preparing = e
	defer func() { r.preparing = nil; resultErr = errors.Join(resultErr, e.close()) }()
	if err := e.prepare(c, serviceID); err != nil {
		return plan, review, err
	}
	return defaultRouteClonePlan(e.plan), e.applyReview(scope), nil
}

func (r *WGListRuntimeSource) acceptWGCommitted(ctx context.Context, started, finished time.Time) error {
	if r == nil || r.self != r || r.closed.Load() {
		return dataplane.ErrWGOperationOwner
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.invalid || r.app.Store != r.store || r.app.Dataplane != r.manager || r.app.SelfUpdateFiles != r.files || r.files.ControlRoot != r.root || applyReviewHash(r.app.catalogSnapshot()) != r.catalog {
		return dataplane.ErrWGOperationOwner
	}
	after := r.store.Get()
	if !defaultRouteCommittedConfig(r.expected, after, r.expected.NetworkPolicy, r.expected.Services, started, finished) {
		return dataplane.ErrReviewChanged
	}
	if err := r.control.Current(ctx); err != nil {
		return err
	}
	if err := r.profile.Current(ctx); err != nil {
		return err
	}
	wan, err := r.reader.ObserveNumericEndpoint(ctx, r.profile)
	if err != nil || !sameWGListSourceWAN(r.wan, wan) {
		return errors.Join(dataplane.ErrWGOperationOwner, err)
	}
	if err := r.scope.AcceptCommitted(ctx, after, started, finished); err != nil {
		return err
	}
	if !reflect.DeepEqual(r.store.Get(), after) {
		return dataplane.ErrReviewChanged
	}
	r.expected = after
	return r.current(ctx)
}
