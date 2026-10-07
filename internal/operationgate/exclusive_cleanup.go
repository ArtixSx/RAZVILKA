package operationgate

import (
	"context"
	"errors"
	"time"
)

// ExclusiveCleanupReview retains only a known original operation's lifetime.
// It never issues a forward context, admits a new operation or authorizes an
// effect. Its concrete owner must independently prove exact Stop/join/ECHILD,
// receipt and bounded cleanup command ownership. There is no DTO constructor.
type ExclusiveCleanupReview struct {
	self  *ExclusiveCleanupReview
	owner *exclusiveContextOwner
}

func (*ExclusiveCleanupReview) String() string   { return "[private original cleanup lifetime]" }
func (*ExclusiveCleanupReview) GoString() string { return "[private original cleanup lifetime]" }

// ReviewExclusiveCleanup must run under the actual live forward admission,
// before cancellation/effects. It cannot be issued later from an expired token.
func (g *Gate) ReviewExclusiveCleanup(ctx context.Context) (*ExclusiveCleanupReview, error) {
	var r *ExclusiveCleanupReview
	err := g.WithExclusiveContext(ctx, func() error {
		o, _ := ctx.Value(exclusiveContextKey{}).(*exclusiveContextOwner)
		r = &ExclusiveCleanupReview{owner: o}
		r.self = r
		return nil
	})
	if err != nil {
		return nil, err
	}
	return r, nil
}

// WithCurrent accepts a new finite cleanup context. The original forward
// deadline and fence do not release its still-held lease; they continue to
// refuse all forward uses. This review does not put that lease in cleanupCtx.
// Synchronous cleanup is joined before original release, without reentrant
// Enter or a Gate lock through the callback. Release must run after cleanup.
func (r *ExclusiveCleanupReview) WithCurrent(ctx context.Context, use func() error) error {
	if r == nil || r.self != r || r.owner == nil || ctx == nil || use == nil {
		return ErrBusy
	}
	deadline, ok := ctx.Deadline()
	if !ok || !time.Now().Before(deadline) {
		if err := ctx.Err(); err != nil {
			return err
		}
		return ErrBusy
	}
	o := r.owner
	check := func() error {
		if err := ctx.Err(); err != nil {
			return err
		}
		o.gate.mu.Lock()
		defer o.gate.mu.Unlock()
		if !o.gate.exclusive || o.gate.active != 1 {
			return ErrBusy
		}
		return nil
	}
	o.mu.Lock()
	if o.closing {
		o.mu.Unlock()
		return ErrBusy
	}
	if err := check(); err != nil {
		o.mu.Unlock()
		return err
	}
	o.uses++
	o.mu.Unlock()
	defer func() {
		o.mu.Lock()
		o.uses--
		if o.uses == 0 {
			o.changed.Broadcast()
		}
		o.mu.Unlock()
	}()
	err := use()
	return errors.Join(err, check())
}
