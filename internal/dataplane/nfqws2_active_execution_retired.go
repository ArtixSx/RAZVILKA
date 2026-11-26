package dataplane

import (
	"context"
	"errors"
)

// No old Apply borrow or live ownership-file read survives a known final
// retirement. The original resource supplies the actual authorized cleanup
// operation; the original final handle supplies only its terminal proof.
func (e *nfqws2ActiveExecution) retiredCleanupCurrent(ctx context.Context) error {
	if e == nil || e.self != e || e.material == nil || e.material.self != e.material || e.material.control == nil || e.material.adapter == nil || e.resource == nil || e.resource.scope == nil || e.cleanupGuard == nil || e.binding == nil {
		return ErrNFQWSScopedOwner
	}
	r := e.resource
	r.scope.mu.Lock()
	h := r.finalOwner
	original := h != nil && h.owner != nil && h.owner.result != nil && r.scope.nfqws[r.binding.ResourceID] == r && r.scope.adapterOwner == e.material.adapter
	r.scope.mu.Unlock()
	if !original {
		return ErrNFQWSScopedOwner
	}
	cleanup, err := r.commandCleanupReview(ctx)
	if err != nil {
		return err
	}
	return cleanup.WithCurrent(ctx, func() error {
		if err := e.material.control.CurrentForCleanup(ctx); err != nil {
			return err
		}
		settled, err := h.owner.result()
		if err != nil || h.VerifyRetiredObservation(ctx, settled.observation()) != nil {
			return errors.Join(ErrNFQWSScopedOwner, err)
		}
		if err := e.cleanupGuard(ctx, h, settled.observation()); err != nil {
			return err
		}
		if err := e.owners(ctx); err != nil {
			return err
		}
		checkReceipt := func() error {
			status, err := e.binding.Inspect(ctx, r.plan, r.root)
			if err != nil || !status.Removed || status.Unknown || status.Promoted {
				return errors.Join(ErrNFQWSScopedOwner, err)
			}
			return nil
		}
		if err := checkReceipt(); err != nil {
			return err
		}
		if err := h.VerifyRetiredObservation(ctx, settled.observation()); err != nil {
			return err
		}
		if err := checkReceipt(); err != nil {
			return err
		}
		return e.material.control.CurrentForCleanup(ctx)
	})
}
