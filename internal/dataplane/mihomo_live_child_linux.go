//go:build linux

package dataplane

import (
	"context"
	"errors"
	"github.com/ArtixSx/razvilka/internal/components"
	"github.com/ArtixSx/razvilka/internal/netidentity"
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
	if err := errors.Join(r.control.ObserveCurrent(ctx), r.node.Current(ctx)); err != nil {
		return err
	}
	return r.adapter.provider.WithCurrent(ctx, func(networkCtx context.Context, current netidentity.Identity) error {
		if current != r.definition.NetworkIdentity {
			return errMihomoLiveMaterial
		}
		return child.WithReadObservation(networkCtx, func(held context.Context, view *components.MihomoLiveObservation) error {
			if !view.BoundTo(child, r.source) {
				return errMihomoLiveMaterial
			}
			profile, err := view.ProfileReference(held)
			if err != nil || profile != r.definition.Profile {
				return errors.Join(errMihomoLiveMaterial, err)
			}
			if _, err := observeMihomoLiveObservation(held, view, r.definition.NetworkIdentity); err != nil {
				return err
			}
			return errors.Join(r.control.ObserveCurrent(held), r.node.Current(held))
		})
	})
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
	if err := r.control.CurrentForCleanupOperation(ctx, cleanup); err != nil {
		return err
	}
	return r.adapter.provider.WithCurrent(ctx, func(networkCtx context.Context, current netidentity.Identity) error {
		if current != r.definition.NetworkIdentity {
			return errMihomoLiveMaterial
		}
		return child.WithCleanupReadObservation(networkCtx, cleanup, func(held context.Context, view *components.MihomoLiveCleanupObservation) error {
			if !view.BoundTo(child, r.source, cleanup) {
				return errMihomoLiveMaterial
			}
			profile, err := view.ProfileReference(held)
			if err != nil || profile != r.definition.Profile {
				return errors.Join(errMihomoLiveMaterial, err)
			}
			if _, err := observeMihomoLiveCleanupObservation(held, view, r.definition.NetworkIdentity); err != nil {
				return err
			}
			return r.control.CurrentForCleanupOperation(held, cleanup)
		})
	})
}
