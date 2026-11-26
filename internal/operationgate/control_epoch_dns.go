package operationgate

import (
	"context"
	"errors"
	"sync"
	"time"
)

// WithDNSReply admits the SAME original finite operation BEFORE observe takes
// the retained Store's bounded negative boundary. The supplied single-use write
// then checks/locks this SAME protected control owner around local socket IO.
// No Gate/Store/catalog/provider call occurs under that control lock. observe
// must perform only the prepared negative observation; socketWrite must perform
// only bounded local reply serialization/write, never a protocol or owner reentry.
func (r *ControlEpochReview) WithDNSReply(ctx context.Context, observe func(func() error) error, socketWrite func() error) error {
	if r == nil || r.self != r || r.gate == nil || ctx == nil || observe == nil || socketWrite == nil {
		return ErrSelfUpdateStopChanged
	}
	deadline, bounded := ctx.Deadline()
	if !bounded || !time.Now().Before(deadline) {
		return errors.Join(ErrSelfUpdateStopChanged, ctx.Err())
	}
	return r.gate.WithExclusiveContext(ctx, func() error {
		var mu sync.Mutex
		active, used := true, false
		var leafErr error
		// Revoke and join an already entered write on EVERY exit, including an
		// observer panic. The retained Gate use closes only after this barrier.
		defer func() {
			mu.Lock()
			active = false
			mu.Unlock()
		}()
		err := observe(func() error {
			mu.Lock()
			defer mu.Unlock()
			if !active || used {
				leafErr = errors.Join(leafErr, ErrSelfUpdateStopChanged)
				return ErrSelfUpdateStopChanged
			}
			used = true
			// Gate admission is already retained outside the Store boundary.
			// check/checkWithMarker inspect only this original control owner.
			r.mu.Lock()
			defer r.mu.Unlock()
			if leafErr = r.check(ctx); leafErr != nil {
				return leafErr
			}
			locked, _, err := lockControlFile(ctx, r.dir)
			if err != nil {
				leafErr = err
				return leafErr
			}
			defer locked.Close()
			if leafErr = r.checkWithMarker(ctx, locked); leafErr != nil {
				return leafErr
			}
			leafErr = errors.Join(socketWrite(), r.checkWithMarker(ctx, locked))
			return leafErr
		})
		mu.Lock()
		active = false
		written := used
		err = errors.Join(err, leafErr)
		mu.Unlock()
		if err == nil && !written {
			return ErrSelfUpdateStopChanged
		}
		return err
	})
}
