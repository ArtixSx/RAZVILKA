package dataplane

import (
	"context"
)

// Called only by the actual original held-tool executor while COMMON retains
// its per-command invocation. A name/argv/digest, receipt DTO or material marker
// alone cannot admit a native syscall.
func WithXraySelectedTCPCommandStart(ctx context.Context, name string, args []string, digest string, begin func() error) error {
	if ctx == nil || begin == nil || !validNetworkPolicyGeneration(digest) {
		return errXraySelectedTCPRuntime
	}
	o, ok := ctx.Value(xrayOperationOwnerKey{}).(*xrayOperationOwner)
	if !ok || o == nil || o.self != o || o.scope == nil || o.material == nil || ctx.Value(xrayOperationMaterialKey{}) != o.material {
		return errXraySelectedTCPRuntime
	}
	o.scope.mu.Lock()
	var resource *XraySelectedTCPExecutionResource
	if len(o.scope.xraySelectedTCP) == 1 {
		for _, r := range o.scope.xraySelectedTCP {
			resource = r
		}
	}
	o.scope.mu.Unlock()
	if resource == nil || resource.owner != o || resource.material != o.material {
		return errXraySelectedTCPRuntime
	}
	return resource.withPolicyCommandStart(ctx, name, args, begin)
}

func (r *XraySelectedTCPExecutionResource) withPolicyCommandStart(ctx context.Context, name string, args []string, begin func() error) error {
	if r == nil || r.self != r || xraySelectedTCPFinite(ctx) != nil {
		return errXraySelectedTCPRuntime
	}
	r.scope.startMu.RLock()
	defer r.scope.startMu.RUnlock()
	invocation, err := observePolicyEffectCommandInvocation(ctx, r.effects, r.rootPath, name, args)
	if err != nil {
		return err
	}
	cleanup := invocation.cleanup
	r.material.barrier.RLock()
	defer r.material.barrier.RUnlock()
	if err := r.owner.checkHeld(ctx, cleanup); err != nil {
		return err
	}
	r.scope.mu.Lock()
	index, err := r.matching()
	if err == nil && !cleanup && (!r.startACK || r.scope.execution.Resources[index].Phase != "listener-ready") {
		err = errXraySelectedTCPRuntime
	}
	r.scope.mu.Unlock()
	if err != nil {
		return err
	}
	if !cleanup {
		r.observationMu.Lock()
		r.selectorUsed = true // Actual durable invocation consumed below; no unused claim afterwards.
		r.observationMu.Unlock()
	}
	return invocation.withStart(ctx, func() error {
		if cleanup {
			capability := r.material.cleanup
			if value := ctx.Value(xrayRetainedOperationKey{}); value != nil {
				op, ok := value.(*xrayRetainedOperation)
				if !ok || op == nil || op.self != op || !op.open.Load() || op.owner == nil || op.owner.execution == nil || op.owner.execution.resource != r || op.forward || op.cleanup == nil {
					return ErrXrayOperationOwner
				}
				capability = op.cleanup
			}
			return r.material.control.WithCleanupStart(ctx, capability, begin)
		}
		return r.material.control.WithStart(ctx, begin)
	})
}

// OriginalOperationContext is comparison for the concrete App dispatcher. It
// grants no effect or cleanup on its own; actual COMMON invocation and control
// admission above remain necessary at every syscall.
func (r *XraySelectedTCPExecutionResource) OriginalOperationContext(ctx context.Context) bool {
	if r == nil || r.self != r || ctx == nil || r.owner == nil || r.scope == nil ||
		ctx.Value(xrayOperationOwnerKey{}) != r.owner || ctx.Value(xrayOperationMaterialKey{}) != r.material {
		return false
	}
	r.scope.mu.Lock()
	defer r.scope.mu.Unlock()
	_, err := r.matching()
	return err == nil
}

func (r *XraySelectedTCPExecutionResource) CleanupContext(ctx context.Context) (context.Context, error) {
	if r == nil || r.self != r || r.owner == nil {
		return nil, errXraySelectedTCPRuntime
	}
	c, err := r.owner.cleanupContext(ctx)
	return c, err
}
