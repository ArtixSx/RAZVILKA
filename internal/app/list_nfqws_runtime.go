package app

import (
	"context"
	"errors"
	"os"
	"reflect"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ArtixSx/razvilka/internal/components"
	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/netidentity"
	"github.com/ArtixSx/razvilka/internal/operationgate"
	"github.com/ArtixSx/razvilka/internal/startuptools"
	"github.com/ArtixSx/razvilka/internal/strategylab"
)

const managedNFQWSListQueue = uint16(200)

// ManagedNFQWSListRuntime is the actual App/startup owner of one literal-IP
// managed NFQ vertical. Its factory accepts no runner, paths, argv, snapshot
// or permission callback. Generic route review and domains remain closed.
type ManagedNFQWSListRuntime struct {
	self            *ManagedNFQWSListRuntime
	mu              sync.Mutex
	app             *App
	manager         *dataplane.Manager
	panel           context.Context
	provider        *netidentity.Provider
	tools           *startuptools.Lease
	inventory       *dataplane.BackendInventory
	gate            *dataplane.NetworkPolicyAdapter
	checks          *dataplane.NetworkPolicyChecks
	control         *operationgate.ControlEpochReview
	active, stopped *managedNFQWSListExecution
	pending         *managedNFQWSListExecution
	closed          bool
}

type managedNFQWSListExecution struct {
	self                                  *managedNFQWSListExecution
	runtime                               *ManagedNFQWSListRuntime
	mu                                    sync.RWMutex
	expected                              config.Config
	catalog                               string
	scope                                 *ListScopeBinding
	component                             *components.ManagedNFQWSRuntimeLease
	source                                *strategylab.SelectedCandidateReview
	material                              *dataplane.NFQWSActiveMaterial
	selection                             *dataplane.NFQWSScopedSelection
	lanAdmission                          *dataplane.LANPolicyCommandAdmission
	plan                                  dataplane.Plan
	compilation                           *DefaultRouteCompilation // original immutable comparison; never an execution grant
	terminal                              *dataplane.NFQWSActiveHandle
	terminalObservation                   dataplane.NFQWSActiveObservation
	pendingContext                        context.Context
	pendingCloseOperation, pendingRelease func()
	pendingStop, retirementKnown          bool
}

type managedNFQWSListOperation struct {
	self      *managedNFQWSListOperation
	execution *managedNFQWSListExecution
	cleanup   *operationgate.ExclusiveCleanupReview
	open      atomic.Bool
}
type managedNFQWSListOperationKey struct{}

// ConfigureReviewedStockNFQWSList is the concrete main/App entrypoint. The
// caller supplies the App service lifetime; each actual operation is separate.
func (a *App) ConfigureReviewedStockNFQWSList(ctx, panel context.Context) (*ManagedNFQWSListRuntime, error) {
	if a == nil || a.Dataplane == nil || a.Store == nil || a.Components == nil || a.StrategyLab == nil || a.SelfUpdateFiles == nil || panel == nil || panel.Err() != nil || ctx == nil {
		return nil, dataplane.ErrNFQWSScopedOwner
	}
	a.managedNFQListMu.Lock()
	defer a.managedNFQListMu.Unlock()
	if a.managedNFQList != nil {
		if a.managedNFQList.closed {
			return nil, dataplane.ErrNFQWSScopedOwner
		}
		return a.managedNFQList, nil
	}
	c, release, err := a.privateExclusiveOperation(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	if _, ok := c.Deadline(); !ok {
		return nil, dataplane.ErrNFQWSScopedOwner
	}
	control, err := a.managedNFQControl(c)
	if err != nil {
		return nil, err
	}
	defer a.closeUnretainedManagedNFQControl(control)
	provider, err := netidentity.NewReviewedStockNC1812Provider(c)
	if err != nil {
		return nil, err
	}
	tools, err := startuptools.AcquireReviewedStockNC1812Policy(panel, provider)
	if err != nil {
		return nil, err
	}
	keep := false
	defer func() {
		if !keep {
			tools.Close()
		}
	}()
	descriptor, err := tools.InventoryTools()
	if err != nil {
		return nil, err
	}
	inventory, err := dataplane.NewReviewedStockNC1812BackendInventory(provider, descriptor)
	if err != nil {
		return nil, err
	}
	policyTools, runner, err := tools.PolicyRuntimeTools()
	if err != nil {
		return nil, err
	}
	r := &ManagedNFQWSListRuntime{app: a, manager: a.Dataplane, panel: panel, provider: provider, tools: tools, inventory: inventory, control: control}
	r.self = r
	lan := &dataplane.LANPolicyRuntime{Runner: runner, IP: policyTools.IP, IPTables: policyTools.IPTables, IP6Tables: policyTools.IP6Tables, ScopeCheck: r.scopeCheck,
		ConsumerCheck: func(c context.Context, p *dataplane.LANPolicyRuntimePlan) error {
			if r.checks == nil {
				return dataplane.ErrNetworkPolicyConsumers
			}
			return r.checks.ConsumerCheck(c, p)
		}}
	binding := &dataplane.LANPolicyReceiptBinding{Runtime: lan, ApplyGuard: r.lanApplyGuard, CleanupGuard: r.lanCleanupGuard,
		RetireCheck: func(c context.Context, p *dataplane.LANPolicyRuntimePlan) error {
			if r.checks == nil {
				return dataplane.ErrNetworkPolicyConsumers
			}
			return r.checks.RetireCheck(c, p)
		}}
	gate, err := dataplane.NewNetworkPolicyAdapter(c, dataplane.NetworkPolicyAssemblyOptions{Mode: dataplane.LANPolicyNFQWSDirectMode, Provider: provider, Binding: binding,
		InventoryCheck: func(c context.Context, n netidentity.Identity, p *dataplane.LANPolicyRuntimePlan) error {
			if r.checks == nil {
				return dataplane.ErrNetworkPolicyConsumers
			}
			return r.checks.InventoryCheck(c, n, p)
		}})
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(r.manager.StateRoot, 0700); err != nil {
		return nil, err
	}
	if err := r.manager.Register(gate); err != nil {
		return nil, err
	}
	r.gate = gate
	r.checks, err = r.manager.BindNetworkPolicyChecks(gate, inventory)
	if err != nil {
		// The actual registered participant cannot be replaced by retrying a
		// failed constructor. Its guards stay closed; a fresh App is required.
		r.closed = true
		a.managedNFQList = r
		return nil, err
	}
	a.retainManagedNFQControl(control)
	a.managedNFQList = r
	keep = true
	return r, nil
}

func (r *ManagedNFQWSListRuntime) operation(ctx context.Context, e *managedNFQWSListExecution, cleanup *operationgate.ExclusiveCleanupReview) (context.Context, func(), error) {
	if r == nil || r.self != r || r.closed || e == nil || e.self != e || e.runtime != r || r.app.Dataplane != r.manager || ctx == nil || ctx.Err() != nil || cleanup == nil {
		return nil, nil, dataplane.ErrNFQWSScopedOwner
	}
	o := &managedNFQWSListOperation{execution: e, cleanup: cleanup}
	o.self = o
	o.open.Store(true)
	ctx = context.WithValue(ctx, managedNFQWSListOperationKey{}, o)
	ctx = startuptools.WithCommandAdmission(ctx, r)
	return ctx, func() { o.open.Store(false) }, nil
}

func (r *ManagedNFQWSListRuntime) executionFor(ctx context.Context) (*managedNFQWSListExecution, *managedNFQWSListOperation, error) {
	if r == nil || r.self != r || r.closed || r.app == nil || r.app.Dataplane != r.manager || ctx == nil || ctx.Err() != nil {
		return nil, nil, dataplane.ErrNFQWSScopedOwner
	}
	o, ok := ctx.Value(managedNFQWSListOperationKey{}).(*managedNFQWSListOperation)
	if !ok || o == nil || o.self != o || !o.open.Load() || o.cleanup == nil || o.execution == nil || o.execution.self != o.execution || o.execution.runtime != r {
		return nil, nil, dataplane.ErrNFQWSScopedOwner
	}
	return o.execution, o, nil
}

// WithStart is called ONLY by the original held-fd startup tool executor.
func (r *ManagedNFQWSListRuntime) WithStart(ctx context.Context, name string, args []string, digest string, begin func() error) error {
	if _, _, err := r.executionFor(ctx); err != nil {
		return err
	}
	if handled, err := dataplane.WithLANPolicyCommandStart(ctx, name, args, digest, begin); handled {
		return err
	}
	return dataplane.WithNFQWSScopedCommandStart(ctx, name, args, digest, begin)
}

func (e *managedNFQWSListExecution) guard(ctx context.Context) error {
	r := e.runtime
	if _, _, err := r.executionFor(ctx); err != nil {
		return err
	}
	return r.app.Operations.WithExclusiveContext(ctx, func() error {
		e.mu.RLock()
		expected := e.expected
		catalogHash := e.catalog
		e.mu.RUnlock()
		if applyReviewHash(r.app.catalogSnapshot()) != catalogHash {
			return dataplane.ErrReviewChanged
		}
		if err := (&DefaultRouteExecutor{app: r.app}).observeConfig(ctx, expected); err != nil {
			return err
		}
		if err := r.control.Current(ctx); err != nil {
			return err
		}
		if err := e.scope.ScopeCheck(ctx, e.plan.LAN); err != nil {
			return err
		}
		if err := e.source.Current(ctx); err != nil {
			return err
		}
		if err := e.component.Check(ctx); err != nil {
			return err
		}
		return (&DefaultRouteExecutor{app: r.app}).observeConfig(ctx, expected)
	})
}

func (r *ManagedNFQWSListRuntime) scopeCheck(ctx context.Context, p *dataplane.LANPolicyRuntimePlan) error {
	e, _, err := r.executionFor(ctx)
	if err != nil || !reflect.DeepEqual(p, e.plan.LAN) {
		return errors.Join(dataplane.ErrReviewChanged, err)
	}
	return e.scope.ScopeCheck(ctx, p)
}

func (r *ManagedNFQWSListRuntime) lanApplyGuard(ctx context.Context, p *dataplane.LANPolicyRuntimePlan, _ dataplane.LANPolicyEffect) error {
	e, _, err := r.executionFor(ctx)
	if err != nil || !reflect.DeepEqual(p, e.plan.LAN) {
		return errors.Join(dataplane.ErrReviewChanged, err)
	}
	return e.guard(ctx)
}

func (r *ManagedNFQWSListRuntime) lanCleanupGuard(ctx context.Context, p *dataplane.LANPolicyRuntimePlan, _ dataplane.LANPolicyEffect) error {
	e, o, err := r.executionFor(ctx)
	if err != nil || !reflect.DeepEqual(p, e.plan.LAN) {
		return errors.Join(dataplane.ErrReviewChanged, err)
	}
	return o.cleanup.WithCurrent(ctx, func() error {
		if err := r.control.CurrentForCleanup(ctx); err != nil {
			return err
		}
		return e.scope.cleanupScopeCheck(ctx, p)
	})
}

func (e *managedNFQWSListExecution) committedGuard(ctx context.Context, h *dataplane.NFQWSActiveHandle, observed dataplane.NFQWSActiveObservation) error {
	if h == nil || h.VerifyOwnerObservation(ctx, observed) != nil {
		return dataplane.ErrNFQWSScopedOwner
	}
	return e.guard(ctx)
}

func (e *managedNFQWSListExecution) cleanupGuard(ctx context.Context, h *dataplane.NFQWSActiveHandle, observed dataplane.NFQWSActiveObservation) error {
	r := e.runtime
	_, o, err := r.executionFor(ctx)
	if err != nil || h == nil {
		return errors.Join(dataplane.ErrNFQWSScopedOwner, err)
	}
	return o.cleanup.WithCurrent(ctx, func() error {
		if err := r.control.CurrentForCleanup(ctx); err != nil {
			return err
		}
		if err := h.VerifyCleanupObservation(ctx, observed); err != nil {
			if err := h.VerifyRetiredObservation(ctx, observed); err != nil {
				return err
			}
			e.mu.Lock()
			e.terminal, e.terminalObservation = h, observed
			e.mu.Unlock()
		}
		if err := e.scope.cleanupScopeCheck(ctx, e.plan.LAN); err != nil {
			return err
		}
		return r.control.CurrentForCleanup(ctx)
	})
}

func (e *managedNFQWSListExecution) close() error {
	var errs []error
	if e.lanAdmission != nil {
		e.lanAdmission.Close()
	}
	if e.selection != nil {
		errs = append(errs, e.selection.Close())
	}
	if e.material != nil {
		errs = append(errs, e.material.Close())
	}
	if e.source != nil {
		errs = append(errs, e.source.Close())
	}
	if e.component != nil {
		errs = append(errs, e.component.Close())
	}
	if e.scope != nil {
		errs = append(errs, e.scope.Close())
	}
	return errors.Join(errs...)
}

// Start consumes one actually saved StrategyLab selection. The service and
// its literals/probe come from this SAME App catalog/config, never request argv.
func (r *ManagedNFQWSListRuntime) Start(ctx context.Context, serviceID, protocol, family string) (dataplane.Execution, error) {
	return r.startReviewed(ctx, serviceID, protocol, family, changeScopeAll, nil)
}

func (r *ManagedNFQWSListRuntime) startReviewed(ctx context.Context, serviceID, protocol, family string, scope changeScope, review *applyReview) (result dataplane.Execution, resultErr error) {
	phase := "original-owner"
	ctx, finishTimings := beginManagedNFQTimings(ctx)
	defer func() { finishTimings(phase, resultErr) }()
	defer func() { resultErr = managedNFQFailureAt(phase, resultErr) }()
	if !r.original() {
		return result, dataplane.ErrNFQWSScopedOwner
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if review != nil && r.active != nil && !r.closed && r.pending == nil && r.panel.Err() == nil {
		_, currentReview, err := r.reviewActiveLocked(ctx, scope)
		if err != nil {
			return result, err
		}
		if *review != currentReview {
			return result, dataplane.ErrReviewChanged
		}
		committed, exists, err := r.manager.Committed()
		if err != nil || !exists || committed.State != "committed" || committed.PlanID != r.active.plan.PlanID || committed.Digest != r.active.plan.Digest || committed.Revision != r.active.plan.Revision {
			return result, errors.Join(dataplane.ErrNFQWSScopedOwner, err)
		}
		if err := r.currentLocked(ctx); err != nil {
			return result, err
		}
		// This describes the current original committed owner after both
		// checks; it is not a new execution or a reconstructed capability.
		return dataplane.Execution{PlanID: committed.PlanID, Digest: committed.Digest, State: committed.State}, nil
	}
	if r.closed || r.active != nil || r.pending != nil || r.panel.Err() != nil {
		return result, dataplane.ErrNFQWSScopedOwner
	}
	phase = "admission"
	c, release, err := r.app.privateExclusiveOperation(ctx)
	if err != nil {
		return result, err
	}
	ownedOperation := true
	defer func() {
		if ownedOperation {
			release()
		}
	}()
	phase = "control"
	if err := r.control.Current(c); err != nil {
		return result, err
	}
	cfg := r.app.Store.Get()
	e := &managedNFQWSListExecution{runtime: r, expected: cfg, catalog: applyReviewHash(r.app.catalogSnapshot())}
	e.self = e
	if review != nil && review.Revision != cfg.Revision {
		return result, dataplane.ErrReviewChanged
	}
	keep := false
	defer func() {
		if !keep {
			resultErr = errors.Join(resultErr, e.close())
		}
	}()
	phase = "prepare"
	compilation, err := e.prepare(c, serviceID, protocol, family)
	if err != nil {
		return result, err
	}
	if review != nil && *review != e.applyReview(compilation, scope) {
		return result, dataplane.ErrReviewChanged
	}
	phase = "lan-admission"
	e.lanAdmission, err = r.manager.ReviewLANPolicyCommandAdmission(c, r.gate, r.inventory, r.control)
	if err != nil {
		return result, err
	}
	phase = "cleanup-capability"
	cleanup, err := r.control.ReviewExclusiveCleanup(c)
	if err != nil {
		return result, err
	}
	phase = "command-owner"
	c, closeOperation, err := r.operation(c, e, cleanup)
	if err != nil {
		return result, err
	}
	defer func() {
		if ownedOperation {
			closeOperation()
		}
	}()
	phase = "bind-execution"
	c, err = e.material.BindExecution(c, r.panel, e.plan, e.selection, r.inventory, r.gate, e.committedGuard, e.cleanupGuard)
	if err != nil {
		return result, err
	}
	c = dataplane.WithReviewGuard(c, e.guard)
	phase = "native-apply"
	result, resultErr = r.app.applyDataplane(c, e.plan, func() (func() error, error) {
		if err := e.guard(c); err != nil {
			return nil, err
		}
		before := r.app.Store.Get()
		if !reflect.DeepEqual(before, cfg) {
			return nil, dataplane.ErrReviewChanged
		}
		started := time.Now()
		undo, err := r.app.Store.CommitNetworkPolicyWithRollback(before, compilation.Policy(), defaultRouteCloneServices(cfg.Services))
		finished := time.Now()
		if err != nil {
			return undo, err
		}
		after := r.app.Store.Get()
		if !defaultRouteCommittedConfig(before, after, compilation.Policy(), cfg.Services, started, finished) {
			return undo, dataplane.ErrReviewChanged
		}
		if err := e.scope.AcceptCommitted(c, after, started, finished); err != nil {
			return undo, err
		}
		e.mu.Lock()
		e.expected = after
		e.mu.Unlock()
		return undo, e.guard(c)
	})
	if resultErr != nil {
		if r.manager.HasPendingManagedNFQWS() {
			e.pendingContext, e.pendingCloseOperation, e.pendingRelease = c, closeOperation, release
			r.pending = e
			ownedOperation, keep = false, true
			r.app.Operations.FenceJournal()
		}
		return result, resultErr
	}
	phase = "terminal-publication"
	if result.State != "committed" {
		return result, dataplane.ErrNFQWSScopedOwner
	}
	r.active = e
	r.stopped = nil
	keep = true
	return result, nil
}

func (r *ManagedNFQWSListRuntime) Current(ctx context.Context) error {
	if !r.original() {
		return dataplane.ErrNFQWSScopedOwner
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.currentLocked(ctx)
}

func (r *ManagedNFQWSListRuntime) currentLocked(ctx context.Context) error {
	if r.active == nil || r.closed {
		return dataplane.ErrNFQWSScopedOwner
	}
	c, release, err := r.app.privateExclusiveOperation(ctx)
	if err != nil {
		return err
	}
	defer release()
	cleanup, err := r.control.ReviewExclusiveCleanup(c)
	if err != nil {
		return err
	}
	c, closeOperation, err := r.operation(c, r.active, cleanup)
	if err != nil {
		return err
	}
	defer closeOperation()
	return r.manager.CheckRetainedManagedNFQWS(c)
}

func (r *ManagedNFQWSListRuntime) Stop(ctx context.Context) error {
	if !r.original() {
		return dataplane.ErrNFQWSScopedOwner
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return dataplane.ErrNFQWSScopedOwner
	}
	if r.pending != nil {
		return r.joinPending(ctx)
	}
	c, release, err := r.app.privateExclusiveOperation(ctx)
	if err != nil {
		return err
	}
	ownedOperation := true
	defer func() {
		if ownedOperation {
			release()
		}
	}()
	cleanup, err := r.app.Operations.ReviewExclusiveCleanup(c)
	if err != nil {
		return err
	}
	if err := r.control.CurrentForCleanupOperation(c, cleanup); err != nil {
		return err
	}
	// Detach only the admitted Stop intent, retain its original typed cleanup
	// review and finite bound through native Wait and COMMON settlement.
	stopCtx, finishStop := context.WithTimeout(context.WithoutCancel(c), 15*time.Second)
	defer finishStop()
	c = stopCtx
	if r.active == nil {
		if r.stopped == nil {
			return dataplane.ErrNFQWSScopedOwner
		}
		e := r.stopped
		if e.terminal == nil || e.terminal.VerifyRetiredObservation(c, e.terminalObservation) != nil {
			return dataplane.ErrNFQWSScopedOwner
		}
		return r.manager.CheckRetiredManagedNFQWSAbsence(c, cleanup, e.terminal, e.terminalObservation, r.checks)
	}
	e := r.active
	c, closeOperation, err := r.operation(c, e, cleanup)
	if err != nil {
		return err
	}
	defer func() {
		if ownedOperation {
			closeOperation()
		}
	}()
	if err := r.manager.StopRetainedManagedNFQWS(c, cleanup); err != nil {
		r.app.Operations.FenceJournal()
		e.pendingContext, e.pendingCloseOperation, e.pendingRelease = c, closeOperation, release
		e.pendingStop = true
		r.pending = e
		ownedOperation = false
		return err
	}
	if e.terminal == nil || e.terminal.VerifyRetiredObservation(c, e.terminalObservation) != nil {
		r.app.Operations.FenceJournal()
		e.pendingContext, e.pendingCloseOperation, e.pendingRelease = c, closeOperation, release
		e.pendingStop = true
		r.pending = e
		ownedOperation = false
		return dataplane.ErrNFQWSScopedOwner
	}
	e.retirementKnown = true
	if err := e.close(); err != nil {
		r.app.Operations.FenceJournal()
		e.pendingContext, e.pendingCloseOperation, e.pendingRelease = c, closeOperation, release
		e.pendingStop = true
		r.pending = e
		ownedOperation = false
		return err
	}
	r.stopped, r.active = e, nil
	return nil
}

func (r *ManagedNFQWSListRuntime) joinPending(ctx context.Context) error {
	e := r.pending
	if ctx == nil || ctx.Err() != nil || e == nil || e.pendingContext == nil || e.pendingRelease == nil || e.pendingCloseOperation == nil {
		return dataplane.ErrNFQWSScopedOwner
	}
	deadline, ok := ctx.Deadline()
	if !ok {
		return dataplane.ErrNFQWSScopedOwner
	}
	bound := time.Until(deadline)
	if bound > 15*time.Second {
		bound = 15 * time.Second
	}
	c, cancel := context.WithTimeout(context.WithoutCancel(e.pendingContext), bound)
	defer cancel()
	if e.pendingStop {
		if !e.retirementKnown {
			_, op, err := r.executionFor(c)
			if err != nil {
				return err
			}
			if err := r.manager.StopRetainedManagedNFQWS(c, op.cleanup); err != nil {
				return err
			}
			if e.terminal == nil || e.terminal.VerifyRetiredObservation(c, e.terminalObservation) != nil {
				return dataplane.ErrNFQWSScopedOwner
			}
			e.retirementKnown = true
		}
	} else if err := r.manager.JoinPendingManagedNFQWS(c); err != nil {
		return err
	}
	if err := e.close(); err != nil {
		return err
	}
	e.pendingCloseOperation()
	e.pendingRelease()
	e.pendingRelease, e.pendingCloseOperation, e.pendingContext = nil, nil, nil
	r.pending = nil
	if e.pendingStop {
		r.active = nil
		r.stopped = e
	}
	// The recovery fence is never cleared by an owner join.
	return nil
}

// Close releases held startup descriptors only after the original consumer
// has settled. Call before cancelling the supplied service lifetime.
func (r *ManagedNFQWSListRuntime) Close(ctx context.Context) error {
	if !r.original() {
		return dataplane.ErrNFQWSScopedOwner
	}
	r.mu.Lock()
	live := r.active != nil || r.pending != nil
	r.mu.Unlock()
	if live {
		if err := r.Stop(ctx); err != nil {
			return err
		}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.active != nil || r.pending != nil {
		return dataplane.ErrNFQWSScopedOwner
	}
	if r.closed {
		return nil
	}
	r.closed = true
	var checksErr error
	if r.checks != nil {
		checksErr = r.checks.Close()
	}
	return errors.Join(checksErr, r.tools.Close())
}

func (r *ManagedNFQWSListRuntime) original() bool {
	return r != nil && r.self == r && r.app != nil && r.app.Dataplane == r.manager && r.app.Store != nil && r.manager != nil && r.panel != nil && r.provider != nil && r.tools != nil && r.inventory != nil && r.gate != nil && r.checks != nil && r.control != nil
}

func (a *App) managedNFQListPending() bool {
	a.managedNFQListMu.Lock()
	r := a.managedNFQList
	a.managedNFQListMu.Unlock()
	if r == nil {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.active != nil || r.pending != nil
}
