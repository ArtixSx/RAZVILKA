package operationgate

import (
	"context"
	"errors"
)

// WithCleanupStart serializes only an original owner's bounded Cmd.Start
// with durable Stop. The caller proves exact receipt, inactive ownership and
// command outside this leaf. cleanup must belong to a still-held actual
// operation of this SAME Gate: either Apply compensation or a fresh Stop
// operation captured by the retained owner before its cleanup effects.
// No forward admission is issued and released operation reviews stay revoked.
// begin must not call Gate, Store, this review, provider/tool checks, Wait or
// the whole cleanup protocol. Only the actual synchronous Start belongs here.
func (r *ControlEpochReview) WithCleanupStart(ctx context.Context, cleanup *ExclusiveCleanupReview, begin func() error) error {
	if r == nil || r.self != r || r.gate == nil || cleanup == nil || cleanup.self != cleanup || cleanup.owner == nil || cleanup.owner.gate != r.gate || begin == nil {
		return ErrSelfUpdateStopChanged
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
		err = begin()
		return errors.Join(err, r.checkWithMarkerMode(ctx, locked, true))
	})
}
