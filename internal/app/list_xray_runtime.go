package app

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"github.com/ArtixSx/razvilka/internal/dataplane"
	"net/netip"
	"reflect"
	"slices"
	"time"
)

const managedXraySelectedTCPListenerPort = uint16(16443)

func (a *App) ConfigureReviewedStockXraySelectedTCPList(ctx, panel context.Context) (*ManagedXraySelectedTCPListRuntime, error) {
	if a == nil {
		return nil, ErrXrayListSource
	}
	a.managedXraySelectedTCPListMu.Lock()
	defer a.managedXraySelectedTCPListMu.Unlock()
	if r := a.managedXraySelectedTCPList; r != nil {
		if !r.original() || r.policy.panel != panel {
			return nil, ErrXrayListSource
		}
		return r, nil
	}
	p, err := a.configureReviewedStockListPolicy(ctx, panel)
	if err != nil {
		return nil, err
	}
	c, end, err := a.privateExclusiveOperation(ctx)
	if err != nil {
		return nil, err
	}
	defer end()
	adapter, err := p.manager.OriginalXraySelectedTCPDispatcher(c)
	if err != nil {
		return nil, err
	}
	r := &ManagedXraySelectedTCPListRuntime{app: a, manager: p.manager, policy: p, adapter: adapter}
	r.self = r
	a.managedXraySelectedTCPList = r
	if err := p.attachXray(r); err != nil {
		a.managedXraySelectedTCPList = nil
		return nil, err
	}
	return r, nil
}

func (e *managedXraySelectedTCPListExecution) prepare(ctx context.Context, serviceID string, candidates ...*xrayAutonomyCandidate) (compilation *DefaultRouteCompilation, resultErr error) {
	phase, phaseStarted := "input", time.Now()
	defer func() { logManagedXrayPrepareFailure(phase, time.Since(phaseStarted), resultErr) }()
	r := e.runtime
	var err error
	if len(candidates) > 1 {
		return nil, ErrXrayListSource
	}
	var candidate *xrayAutonomyCandidate
	if len(candidates) == 1 {
		candidate = candidates[0]
		if candidate == nil || candidate.self != candidate || candidate.app != r.app {
			return nil, ErrXrayListSource
		}
		phase, phaseStarted = "scope-acquire", time.Now()
		e.scope, e.finiteScope, err = r.app.autonomyXrayScopeOwner(ctx)
	} else {
		phase, phaseStarted = "scope-acquire", time.Now()
		e.finiteScope, err = newReviewedStockXrayFiniteScopeBinding(ctx, r.app, r.policy.provider)
	}
	if err != nil {
		return nil, err
	}
	phase, phaseStarted = "source-review", time.Now()
	e.source, err = r.app.reviewXrayListRuntimeSourceOwner(ctx, e.scopeOwner(), serviceID, r.adapter, candidate)
	if err != nil {
		return nil, err
	}
	phase, phaseStarted = "source-prepare", time.Now()
	e.preparation, err = e.source.prepare(ctx, true)
	if err != nil {
		return nil, err
	}
	phase, phaseStarted = "shape", time.Now()
	c := e.preparation.compilation
	lan := c.LAN()
	if lan == nil || len(lan.Ingress) != 1 || len(lan.Ingress[0].Sources) != 1 || !e.scopeOwner().hasPhysicalIssuer() {
		return nil, ErrDefaultRouteCapability
	}
	client, err := netip.ParsePrefix(lan.Ingress[0].Sources[0])
	if err != nil || !client.Addr().Is4() || client.Bits() != 32 {
		return nil, ErrDefaultRouteCapability
	}
	input := (&DefaultRouteExecutor{app: r.app}).input(c, e.source.expected)
	if len(input.Routes) != 1 || !slices.Equal(input.Routes[0].CIDRs, e.source.frozen.CIDRs) {
		return nil, ErrDefaultRouteCapability
	}
	var address netip.Addr
	for _, segment := range e.scopeOwner().segments() {
		if segment.Interface != lan.Ingress[0].Interface {
			continue
		}
		for _, raw := range segment.LinkAddresses {
			p, parseErr := netip.ParsePrefix(raw)
			if parseErr != nil {
				return nil, ErrListScopeChanged
			}
			if !p.Addr().Is4() || !p.Addr().IsGlobalUnicast() || p.Addr().IsLoopback() {
				continue
			}
			if address.IsValid() {
				return nil, ErrListScopeChanged
			}
			address = p.Addr()
		}
	}
	if !address.IsValid() || address == client.Addr() {
		return nil, ErrListScopeChanged
	}
	port := managedXraySelectedTCPListenerPort
	if e.previous != nil {
		if e.previous.listener.Port() == managedXraySelectedTCPListenerPort {
			port++
		} else if e.previous.listener.Port() != managedXraySelectedTCPListenerPort+1 {
			return nil, ErrXrayListSource
		}
	}
	e.listener = netip.AddrPortFrom(address, port)
	phase, phaseStarted = "primary-review", time.Now()
	err = e.reviewPrimary(ctx, lan.Ingress[0].Interface, address)
	if err != nil {
		return nil, err
	}
	spec := dataplane.XraySelectedTCPRedirectSpec{Schema: 1, Generation: c.Digest(), ServiceID: e.source.service, NodeID: e.source.node.Reference().NodeID,
		LAN: lan, Destinations: slices.Clone(e.source.frozen.CIDRs), Ports: []dataplane.XraySelectedTCPPortRange{{First: 443, Last: 443}}, Listener: e.listener}
	phase, phaseStarted = "material-review", time.Now()
	e.material, err = dataplane.ReviewXrayOperationMaterial(ctx, r.manager, r.policy.control, r.adapter, e.preparation.proof, spec)
	if err != nil {
		return nil, err
	}
	phase, phaseStarted = "plan-build", time.Now()
	plan, err := dataplane.BuildManagedXraySelectedTCPList(ctx, input, e.material, time.Now().UTC())
	if err != nil || !plan.Ready {
		return nil, errors.Join(ErrDefaultRouteCapability, err)
	}
	plan.Digest = defaultRouteDigest(struct{ Plan, Policy string }{plan.Digest, c.Digest()})
	var nonce [8]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, err
	}
	plan.PlanID = "dp-" + plan.Digest[:16] + "-" + hex.EncodeToString(nonce[:])
	e.plan = defaultRouteClonePlan(plan)
	phase, phaseStarted = "closing-current", time.Now()
	return c, errors.Join(e.primaryCurrent(ctx), e.preparation.current(ctx))
}

func (e *managedXraySelectedTCPListExecution) close() error {
	if e == nil || e.self != e {
		return ErrXrayListSource
	}
	// Never erase a live/unknown native owner's original compensation.
	if e.material != nil {
		if err := e.material.Close(); err != nil {
			return err
		}
	}
	var err error
	if e.terminal != nil {
		err = errors.Join(err, e.terminal.Close())
	}
	if e.lanAdmission != nil {
		e.lanAdmission.Close()
	}
	if e.preparation != nil {
		err = errors.Join(err, e.preparation.close())
	}
	if e.source != nil {
		started := time.Now()
		closeErr := e.source.Close()
		err = errors.Join(err, closeErr)
		logManagedXrayReviewClose("source-close", time.Since(started), closeErr)
	}
	if e.scope != nil || e.finiteScope != nil {
		started := time.Now()
		closeErr := e.scopeOwner().Close()
		err = errors.Join(err, closeErr)
		logManagedXrayReviewClose("scope-close", time.Since(started), closeErr)
	}
	return err
}

func (r *ManagedXraySelectedTCPListRuntime) Start(ctx context.Context, serviceID string) (dataplane.Execution, error) {
	return r.startReviewed(ctx, serviceID, changeScopeAll, nil)
}

func (r *ManagedXraySelectedTCPListRuntime) startReviewed(ctx context.Context, serviceID string, scope changeScope, review *applyReview) (result dataplane.Execution, resultErr error) {
	if !r.original() {
		return result, ErrXrayListSource
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.pending != nil || r.preparing != nil {
		return result, ErrXrayListSource
	}
	if r.active != nil {
		if review == nil {
			return result, ErrXrayListSource
		}
		_, actual, err := r.reviewActiveLocked(ctx, scope)
		if err != nil || actual != *review {
			return result, errors.Join(dataplane.ErrReviewChanged, err)
		}
		committed, found, err := r.manager.Committed()
		if err != nil || !found || committed.PlanID != r.active.plan.PlanID || committed.Digest != r.active.plan.Digest {
			return result, errors.Join(ErrXrayListSource, err)
		}
		return dataplane.Execution{PlanID: committed.PlanID, Digest: committed.Digest, State: committed.State}, nil
	}
	if r.app.Store.Get().ServiceControl.Stopped {
		return result, ErrXrayListSource
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
	if err := r.policy.control.Current(c); err != nil {
		return result, err
	}
	cfg := r.app.Store.Get()
	if cfg.ServiceControl.Stopped {
		return result, ErrXrayListSource
	}
	e := &managedXraySelectedTCPListExecution{runtime: r}
	e.self = e
	r.preparing = e
	keep := false
	defer func() {
		r.preparing = nil
		if !keep {
			resultErr = errors.Join(resultErr, e.close())
		}
	}()
	if review != nil && review.Revision != cfg.Revision {
		return result, dataplane.ErrReviewChanged
	}
	compilation, err := e.prepare(c, serviceID)
	if err != nil {
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
	c, closeOperation, err := r.operation(c, e, cleanup)
	if err != nil {
		return result, err
	}
	defer func() {
		if owned {
			closeOperation()
		}
	}()
	c, err = e.material.BindExecution(c, r.policy.panel, e.plan, r.policy.inventory, r.policy.gate, r.policy.checks, e.committedGuard, e.cleanupGuard)
	if err != nil {
		return result, err
	}
	c = dataplane.WithReviewGuard(c, e.guard)
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
		if err := e.source.acceptCommitted(c, started, finished); err != nil {
			return undo, err
		}
		return undo, e.guard(c)
	})
	if resultErr != nil {
		if r.manager.HasPendingManagedXraySelectedTCP() {
			e.pendingContext, e.pendingCloseOperation, e.pendingRelease = c, closeOperation, release
			r.pending = e
			owned, keep = false, true
			r.app.Operations.FenceJournal()
		}
		return result, resultErr
	}
	if result.State != "committed" {
		return result, ErrXrayListSource
	}
	r.active = e
	keep = true
	return result, nil
}

func (r *ManagedXraySelectedTCPListRuntime) Current(ctx context.Context) error {
	if !r.original() {
		return ErrXrayListSource
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.currentLocked(ctx)
}
func (r *ManagedXraySelectedTCPListRuntime) currentLocked(ctx context.Context) error {
	if r.active == nil || r.pending != nil || r.closed {
		return ErrXrayListSource
	}
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	c, end, err := r.app.privateExclusiveOperation(ctx)
	if err != nil {
		return err
	}
	defer end()
	cleanup, err := r.policy.control.ReviewExclusiveCleanup(c)
	if err != nil {
		return err
	}
	c, endOperation, err := r.operation(c, r.active, cleanup)
	if err != nil {
		return err
	}
	defer endOperation()
	return r.manager.CheckRetainedManagedXraySelectedTCP(c)
}

func (r *ManagedXraySelectedTCPListRuntime) Stop(ctx context.Context) error {
	if !r.original() {
		return ErrXrayListSource
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.pending != nil {
		pair := r.pending.previous != nil && r.pending.source != nil && r.pending.source.autonomy != nil
		if err := r.joinPending(ctx, pair); err != nil {
			return err
		}
		if !pair {
			return nil
		}
		// The original cleanup lease is transferred to the surviving owner.
		// Public service Stop performs its Store CAS through the same path.
		e := r.pending
		if e == nil || !e.pendingStop {
			return ErrXrayListSource
		}
		before := r.app.Store.Get()
		e.stopBefore = &before
		return r.stopServiceRuntimeLocked(ctx, e)
	}
	e := r.active
	if e == nil {
		e = r.stopped
	}
	if e == nil {
		return ErrXrayListSource
	}
	c, release, err := r.app.privateExclusiveOperation(ctx)
	if err != nil {
		return err
	}
	owned := true
	defer func() {
		if owned {
			release()
		}
	}()
	cleanup, err := r.app.Operations.ReviewExclusiveCleanup(c)
	if err != nil {
		return err
	}
	if err := r.policy.control.CurrentForCleanupOperation(c, cleanup); err != nil {
		return err
	}
	c, cancel := context.WithTimeout(context.WithoutCancel(c), 15*time.Second)
	defer cancel()
	c, end, err := r.operation(c, e, cleanup)
	if err != nil {
		return err
	}
	defer func() {
		if owned {
			end()
		}
	}()
	if e.terminal != nil {
		return e.terminal.ObserveRetired(c, cleanup)
	}
	terminal, err := r.manager.StopRetainedManagedXraySelectedTCP(c, cleanup)
	if err == nil {
		e.terminal = terminal
		r.stopped, r.active = e, nil
		return nil
	}
	e.pendingContext, e.pendingCloseOperation, e.pendingRelease = c, end, release
	e.pendingStop = true
	r.pending = e
	owned = false
	r.app.Operations.FenceJournal()
	return err
}

func (r *ManagedXraySelectedTCPListRuntime) joinPending(ctx context.Context, retainForStop ...bool) error {
	if len(retainForStop) > 1 {
		return ErrXrayListSource
	}
	e := r.pending
	if xrayListSourceContext(ctx) != nil || e == nil || e.pendingContext == nil || e.pendingCloseOperation == nil || e.pendingRelease == nil {
		return ErrXrayListSource
	}
	d, _ := ctx.Deadline()
	bound := time.Until(d)
	if bound > 15*time.Second {
		bound = 15 * time.Second
	}
	c, end := context.WithTimeout(context.WithoutCancel(e.pendingContext), bound)
	defer end()
	_, op, err := r.executionFor(c)
	if err != nil {
		return err
	}
	if e.previous != nil && e.source != nil && e.source.autonomy != nil {
		committed := e.pendingReplacementComplete
		if !committed {
			var err error
			committed, err = r.manager.JoinPendingManagedXrayReplacement(c, len(retainForStop) == 1 && retainForStop[0])
			if err != nil {
				return err
			}
			e.pendingReplacementComplete = committed
		}
		if committed {
			if err := e.previous.close(); err != nil {
				return err
			}
			if err := r.app.recordAutonomyRoute(c, e.source.autonomy.policy, e.source.autonomy.spec, e.source.selected); err != nil {
				return err
			}
			r.active = e
		} else {
			if err := e.close(); err != nil {
				return err
			}
			r.active = e.previous
		}
		stop := len(retainForStop) == 1 && retainForStop[0]
		if stop {
			// Transfer the SAME held Gate lifetime and preissued cleanup review.
			// This private App association issues no new Gate/native permission.
			survivor := r.active
			next, closeNext, err := r.operation(c, survivor, op.cleanup)
			if err != nil {
				return err
			}
			release := e.pendingRelease
			e.pendingCloseOperation()
			e.pendingContext, e.pendingCloseOperation, e.pendingRelease = nil, nil, nil
			e.previous = nil
			survivor.pendingContext, survivor.pendingCloseOperation, survivor.pendingRelease = next, closeNext, release
			survivor.pendingStop = true
			r.pending = survivor
			return nil
		}
		e.pendingCloseOperation()
		e.pendingRelease()
		e.pendingContext, e.pendingCloseOperation, e.pendingRelease = nil, nil, nil
		e.previous, r.pending = nil, nil
		return nil
	}
	var terminal *dataplane.XraySelectedTCPTerminal
	if e.pendingStop {
		terminal, err = r.manager.StopRetainedManagedXraySelectedTCP(c, op.cleanup)
	} else {
		terminal, err = r.manager.JoinPendingManagedXraySelectedTCP(c)
	}
	if err != nil {
		return err
	}
	e.terminal = terminal
	e.pendingCloseOperation()
	e.pendingRelease()
	e.pendingContext, e.pendingCloseOperation, e.pendingRelease = nil, nil, nil
	r.pending, r.active, r.stopped = nil, nil, e
	return nil
}

func (r *ManagedXraySelectedTCPListRuntime) Close(ctx context.Context) error {
	if r == nil || r.self != r || r.app == nil || r.app.managedXraySelectedTCPList != r {
		return ErrXrayListSource
	}
	r.mu.Lock()
	closed, live := r.closed, r.active != nil || r.pending != nil
	r.mu.Unlock()
	if closed {
		return r.policy.releaseXray(r)
	}
	if live {
		if err := r.Stop(ctx); err != nil {
			return err
		}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.active != nil || r.pending != nil || r.preparing != nil {
		return ErrXrayListSource
	}
	if r.stopped != nil {
		if err := r.stopped.close(); err != nil {
			return err
		}
	}
	r.closed = true
	r.closeErr = r.policy.releaseXray(r)
	return r.closeErr
}
