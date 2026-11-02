package operationgate

import (
	"context"
	"errors"
	"time"
)

// WithCleanupRemove linearizes one original owner's removal syscall with
// durable Stop. It requires a still-held cleanup operation of this SAME Gate;
// the caller must verify its exact held file preimage before admission and
// perform directory sync/readback afterwards. No file ownership is issued.
// remove must not call Gate, Store, this review, Wait or an entire protocol.
func (r *ControlEpochReview) WithCleanupRemove(ctx context.Context, cleanup *ExclusiveCleanupReview, remove func() error) error {
	if r == nil || r.self != r || r.gate == nil || cleanup == nil || cleanup.self != cleanup || cleanup.owner == nil || cleanup.owner.gate != r.gate || remove == nil || ctx == nil {
		return ErrSelfUpdateStopChanged
	}
	deadline, bounded := ctx.Deadline()
	if !bounded || !time.Now().Before(deadline) {
		return errors.Join(ErrSelfUpdateStopChanged, ctx.Err())
	}
	return cleanup.WithCurrent(ctx, func() error {
		r.mu.Lock()
		defer r.mu.Unlock()
		if err := r.checkWithMarkerMode(ctx, r.lock, true); err != nil {
			return err
		}
		locked, _, err := lockControlFile(ctx, r.dir)
		if err != nil {
			return err
		}
		defer locked.Close()
		if err := r.checkWithMarkerMode(ctx, locked, true); err != nil {
			return err
		}
		err = remove()
		return errors.Join(err, r.checkWithMarkerMode(ctx, locked, true))
	})
}
