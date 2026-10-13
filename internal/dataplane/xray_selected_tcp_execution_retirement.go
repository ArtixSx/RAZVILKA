package dataplane

import (
	"context"
	"errors"
	"reflect"
)

func (e *xraySelectedTCPExecution) rollback(ctx context.Context) error {
	if e == nil || e.self != e || e.material == nil || xraySelectedTCPFinite(ctx) != nil {
		return ErrXrayOperationOwner
	}
	e.mu.Lock()
	r := e.resource
	e.mu.Unlock()
	if r == nil {
		if e.replacement != nil {
			return e.replacement.unusedCandidate(ctx, e)
		}
		return e.preResource.unused(ctx, e)
	} // No original resource publication, no native/effect issuer.
	bound, err := r.owner.cleanupContext(networkPolicyConsumerContext(ctx, e.plan))
	if err != nil {
		return err
	}
	if err := e.removeOriginalEffects(bound); err != nil {
		return err
	}
	// A's original selectors no longer admit new flows. Existing A-only
	// connections must settle naturally before signalling its original child;
	// candidate C and its distinct listener are not part of this observation.
	if p := e.replacement; p != nil && p.self == p && p.prior != nil && p.prior.execution == e {
		if !p.committed.Load() || p.closed.Load() || p.candidateCurrent(ctx) != nil {
			return ErrXrayOperationOwner
		}
		if err := xraySelectedTCPObserveConntrackSettled(bound, r.scope.networkIdentity.provider, r.definition.NetworkIdentity, r.definition.Match); err != nil {
			return err
		}
		if err := p.candidateCurrent(ctx); err != nil {
			return err
		}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.startACK {
		// DiscardUnused takes this same mutex itself; release before joining its
		// original version child and publishing actual never-started settlement.
		r.mu.Unlock()
		err := r.discardUnused(bound, false)
		r.mu.Lock()
		if err == nil {
			e.mu.Lock()
			e.retired = true
			e.mu.Unlock()
		}
		return err
	}
	if err := r.stopOriginalNative(bound); err != nil {
		return err
	}
	r.commonMu.Lock()
	if r.common != nil && (!r.common.status.Removed || r.common.status.Unknown || r.common.current(bound) != nil) {
		r.commonMu.Unlock()
		return ErrPolicyAdditionUnknown
	}
	r.commonMu.Unlock()
	r.scope.mu.Lock()
	i, err := r.matching()
	if err == nil {
		r.stopped, r.active = true, false
		r.scope.execution.Resources[i].State, r.scope.execution.Resources[i].Phase = "removed", "removed"
		err = r.scope.persist()
	}
	r.scope.mu.Unlock()
	if err == nil {
		e.mu.Lock()
		e.retired = true
		e.mu.Unlock()
	}
	return err
}

func (e *xraySelectedTCPExecution) verifyRollback(ctx context.Context) (bool, error) {
	if e == nil || e.self != e || xraySelectedTCPFinite(ctx) != nil {
		return false, ErrXrayOperationOwner
	}
	e.mu.Lock()
	r := e.resource
	retired := e.retired
	e.mu.Unlock()
	if r == nil {
		var err error
		if e.replacement != nil {
			err = e.replacement.unusedCandidate(ctx, e)
		} else {
			err = e.preResource.unused(ctx, e)
		}
		return err == nil, err
	}
	if !retired {
		return false, ErrXrayOperationOwner
	}
	bound, err := r.owner.cleanupContext(networkPolicyConsumerContext(ctx, e.plan))
	if err != nil {
		return false, err
	}
	r.observationMu.RLock()
	defer r.observationMu.RUnlock()
	if r.startACK {
		if !r.stopped || r.child == nil || r.child.Joined(bound) != nil || xraySelectedTCPObserveListenerAbsent(bound, r.scope.networkIdentity.provider, r.definition.NetworkIdentity, r.definition.Match.Listener) != nil ||
			xraySelectedTCPObserveConntrackSettled(bound, r.scope.networkIdentity.provider, r.definition.NetworkIdentity, r.definition.Match) != nil {
			return false, ErrPolicyAdditionUnknown
		}
	} else if r.child != nil || r.selectorUsed || r.versionChild != nil && r.versionChild.Joined(bound) != nil {
		return false, ErrPolicyAdditionUnknown
	}
	r.commonMu.Lock()
	defer r.commonMu.Unlock()
	if r.common != nil && (!r.common.status.Removed || r.common.status.Unknown || r.common.current(bound) != nil) {
		return false, ErrPolicyAdditionUnknown
	}
	r.scope.mu.Lock()
	defer r.scope.mu.Unlock()
	i, err := r.matching()
	if err != nil || validateXraySelectedTCPExecutionResource(r.scope.execution.Resources[i], true) != nil {
		return false, errors.Join(ErrPolicyAdditionUnknown, err)
	}
	return true, nil
}

func xraySelectedTCPExecutionForRoutes(ctx context.Context, original *ProxyTunnelAdapter, routes RoutePlan, root string) (*xraySelectedTCPExecution, bool, error) {
	xraySelectedTCPExecutions.Lock()
	e := xraySelectedTCPExecutions.live[original]
	xraySelectedTCPExecutions.Unlock()
	if ctx == nil || ctx.Value(xraySelectedTCPExecutionKey{}) == nil {
		if e != nil {
			return nil, true, ErrXrayOperationOwner
		}
		return nil, false, nil
	}
	value, ok := ctx.Value(xraySelectedTCPExecutionKey{}).(*xraySelectedTCPExecution)
	if !ok || value == nil || value.self != value || !xraySelectedTCPAssociated(e, value) || !reflect.DeepEqual(routes, value.plan.RoutePlanFor("xray")) {
		return nil, true, ErrXrayOperationOwner
	}
	return xraySelectedTCPExecutionFor(ctx, original, value.plan, root)
}

// Every non-lifecycle entry refuses a selected owner unless Manager installed
// its actual fresh retained read/cleanup operation. It never repairs a runtime.
func xraySelectedTCPOriginalAssociated(original *ProxyTunnelAdapter) bool {
	xraySelectedTCPExecutions.Lock()
	defer xraySelectedTCPExecutions.Unlock()
	return xraySelectedTCPExecutions.live[original] != nil
}

func xraySelectedTCPObserveOriginalAssociated(ctx context.Context, original *ProxyTunnelAdapter) error {
	xraySelectedTCPExecutions.Lock()
	e := xraySelectedTCPExecutions.live[original]
	xraySelectedTCPExecutions.Unlock()
	if e == nil || e.material == nil || !e.material.RetainedOperationContext(ctx) {
		return ErrXrayOperationOwner
	}
	if err := e.material.current(ctx, false); err != nil {
		return err
	}
	return e.health(ctx)
}
