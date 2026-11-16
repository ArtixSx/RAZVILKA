package dataplane

import (
	"context"
	"errors"
)

func sameBootCurrentReadContext(parent, child context.Context) error {
	if parent == nil || child == nil || parent.Err() != nil || child.Err() != nil {
		return ErrMihomoLiveRetirement
	}
	if limit, bounded := parent.Deadline(); bounded {
		inner, ok := child.Deadline()
		if !ok || inner.After(limit) {
			return ErrMihomoLiveRetirement
		}
	}
	return nil
}

// Current is a pure synchronous observation. Its two original tool checks
// share ONLY this source's existing byte observation; every process, control,
// provider and private-file read remains. Closing finishes before Run/delete,
// publication or any other effect in the caller. An existing absence scope
// uses the producer's original nested path, not a second image or authority.
func (o *mihomoSameBootCleanup) observeOriginalCurrent(ctx context.Context) error {
	r := o.freezeAbsenceRead()
	if r == nil {
		return o.currentUnscoped(ctx)
	}
	original, supported := r.read.source.(domainTCPToolObserver)
	if !supported {
		return o.currentUnscoped(ctx)
	}
	if err := r.current(ctx); err != nil {
		return err
	}
	var callbackErr error
	uses := 0
	err := original.WithReadOnlyToolObservation(ctx, r.read.tools.Identity, r.read.tools.ReviewSHA256, func(observed context.Context) error {
		uses++
		if uses != 1 {
			callbackErr = errors.Join(callbackErr, ErrMihomoLiveRetirement)
			return callbackErr
		}
		if err := errors.Join(sameBootCurrentReadContext(ctx, observed), r.current(observed)); err != nil {
			callbackErr = err
			return callbackErr
		}
		callbackErr = errors.Join(o.currentUnscoped(observed), r.current(observed), sameBootCurrentReadContext(ctx, observed))
		return callbackErr
	})
	if uses != 1 {
		err = errors.Join(err, ErrMihomoLiveRetirement)
	}
	return errors.Join(err, callbackErr, r.current(ctx), ctx.Err())
}
