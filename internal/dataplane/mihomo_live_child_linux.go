//go:build linux

package dataplane

import (
	"context"
	"errors"
	"github.com/ArtixSx/razvilka/internal/operationgate"
)

// nativeCurrent is the read-only child/kernel portion of live health. It
// grants no service PASS or TUN/policy authority; the transaction owns those
// independent opening/closing checks before ACTIVE or Commit.
func (r *mihomoLiveResource) nativeCurrent(ctx context.Context) error {
	if r == nil || r.self != r || r.scope == nil || r.adapter == nil || r.source == nil || r.node == nil || r.control == nil || !r.adapter.RegisteredWith(r.scope.manager) || !r.source.OwnedBy(r.adapter.components) {
		return errMihomoLiveMaterial
	}
	r.mu.Lock()
	child, closed, closeErr := r.child, r.closed, r.closeErr
	r.mu.Unlock()
	if child == nil || closed || closeErr != nil {
		return errors.Join(errMihomoLiveMaterial, closeErr)
	}
	if r.source.Reference() != r.definition.Source || r.node.Reference() != r.definition.Node {
		return errMihomoLiveMaterial
	}
	if err := errors.Join(r.control.ObserveCurrent(ctx), r.source.Current(ctx), r.node.Current(ctx)); err != nil {
		return err
	}
	profile, err := child.ProfileReference(ctx)
	if err != nil || profile != r.definition.Profile {
		return errors.Join(errMihomoLiveMaterial, err)
	}
	if _, err := observeMihomoLiveProcess(ctx, child, r.adapter.provider, r.definition.NetworkIdentity); err != nil {
		return err
	}
	return errors.Join(r.control.ObserveCurrent(ctx), r.source.Current(ctx), r.node.Current(ctx))
}

func (r *mihomoLiveResource) nativeCleanupCurrent(ctx context.Context, cleanup *operationgate.ExclusiveCleanupReview) error {
	if r == nil || r.self != r || r.adapter == nil || r.scope == nil || r.control == nil || r.source == nil {
		return errMihomoLiveMaterial
	}
	r.mu.Lock()
	child := r.child
	r.mu.Unlock()
	if child == nil || !r.adapter.RegisteredWith(r.scope.manager) || r.source.Reference() != r.definition.Source {
		return errMihomoLiveMaterial
	}
	if err := errors.Join(r.control.CurrentForCleanupOperation(ctx, cleanup), r.source.Current(ctx)); err != nil {
		return err
	}
	profile, err := child.ProfileReferenceForCleanup(ctx, cleanup)
	if err != nil || profile != r.definition.Profile {
		return errors.Join(errMihomoLiveMaterial, err)
	}
	_, err = observeMihomoLiveCleanupProcess(ctx, child, cleanup, r.adapter.provider, r.definition.NetworkIdentity)
	return err
}
