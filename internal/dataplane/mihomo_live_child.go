package dataplane

import (
	"context"
	"errors"

	"github.com/ArtixSx/razvilka/internal/operationgate"
)

// startNative reserves the original opaque child before any descriptor,
// validation or runtime Start. The two COMMON methods are owned by the same
// concrete resource; a DTO or a caller-supplied effect callback cannot launch.
func (r *mihomoLiveResource) startNative(ctx context.Context, cleanup *operationgate.ExclusiveCleanupReview) error {
	if r == nil || r.self != r || r.adapter == nil || r.scope == nil || r.scope.manager == nil || r.control == nil || r.childControl == nil || r.childControl == r.control || r.source == nil || r.node == nil || r.profile == nil || !r.adapter.RegisteredWith(r.scope.manager) || !r.source.OwnedBy(r.adapter.components) {
		return errMihomoLiveMaterial
	}
	if err := r.node.Current(ctx); err != nil {
		return err
	}
	if r.node.Reference() != r.definition.Node || r.source.Reference() != r.definition.Source {
		return errMihomoLiveMaterial
	}
	if r.childControl.Reference() != r.control.Reference() {
		return errMihomoLiveMaterial
	}
	if err := errors.Join(r.control.Current(ctx), r.childControl.Current(ctx), r.control.CurrentForCleanupOperation(ctx, cleanup), r.childControl.CurrentForCleanupOperation(ctx, cleanup)); err != nil {
		return err
	}
	profile, err := r.source.ReviewProfileReference(ctx, r.profile)
	if err != nil || profile != r.definition.Profile {
		return errors.Join(errMihomoLiveMaterial, err)
	}
	r.mu.Lock()
	if r.reserveAttempted || r.closed || r.closeErr != nil || r.child != nil {
		r.mu.Unlock()
		return errMihomoLiveMaterial
	}
	r.reserveAttempted = true
	r.cleanup = cleanup
	r.mu.Unlock()
	child, err := r.source.ReserveLiveChild(ctx, r.profile, r.childControl, cleanup)
	if err != nil {
		r.mu.Lock()
		r.nativeUnused = child == nil
		r.mu.Unlock()
		return err
	}
	r.mu.Lock()
	r.child = child
	r.mu.Unlock()
	// The child remains visible to original cleanup even if the writer or the
	// admission panics; only its own sole Wait can settle native completion.
	if err := r.beforeValidation(ctx, child); err != nil {
		return err
	}
	return child.StartAdmitted(ctx, r.admitNativeStart)
}

// cleanupNative obtains no authority from historical PID fields or a prior
// Apply lease. The original component child requires this fresh SAME-Gate
// cleanup review against the dedicated retained control owner.
func (r *mihomoLiveResource) cleanupNative(ctx context.Context, cleanup *operationgate.ExclusiveCleanupReview) error {
	if r == nil || r.self != r || r.control == nil || cleanup == nil {
		return errMihomoLiveMaterial
	}
	if err := r.control.CurrentForCleanupOperation(ctx, cleanup); err != nil {
		return err
	}
	r.mu.Lock()
	child, closed, closeErr, reserveAttempted, unused := r.child, r.closed, r.closeErr, r.reserveAttempted, r.nativeUnused
	r.mu.Unlock()
	if closeErr != nil {
		return errors.Join(errMihomoLiveMaterial, closeErr)
	}
	if closed {
		return nil
	}
	if child == nil {
		if reserveAttempted && !unused {
			return errMihomoLiveMaterial
		}
		// No child exists only before reservation; no Start can be manufactured
		// by cleanup. The COMMON owner still has to settle the unused resource.
		return nil
	}
	return child.Cleanup(ctx, cleanup)
}
