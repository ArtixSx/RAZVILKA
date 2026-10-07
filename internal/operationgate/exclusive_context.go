package operationgate

import (
	"context"
	"errors"
	"sync"
)

// The key and owner are private. A Gate snapshot, label, holder description,
// detached reference or an existing unscoped Exclusive release cannot create
// this capability. It is issued only together with the original admission.
type exclusiveContextKey struct{}

type exclusiveContextOwner struct {
	gate     *Gate
	original context.Context
	mu       sync.Mutex
	changed  *sync.Cond
	closing  bool
	uses     uint64
}

// ExclusiveContext admits an original exclusive operation and attaches its
// private capability to the returned context. Cancellation never releases the
// operation: the owner must first join its work and then call release. Release
// refuses new uses and waits for synchronous admitted uses to return. It must
// not be called from inside one of those uses.
func (g *Gate) ExclusiveContext(ctx context.Context) (context.Context, func(), error) {
	if g == nil || ctx == nil {
		return nil, nil, ErrBusy
	}
	release, err := g.Exclusive(ctx)
	if err != nil {
		return nil, nil, err
	}
	o := &exclusiveContextOwner{gate: g, original: ctx}
	o.changed = sync.NewCond(&o.mu)
	var once sync.Once
	closeOwner := func() {
		once.Do(func() {
			o.mu.Lock()
			o.closing = true
			for o.uses != 0 {
				o.changed.Wait()
			}
			o.mu.Unlock()
			release()
		})
	}
	return context.WithValue(ctx, exclusiveContextKey{}, o), closeOwner, nil
}

// WithExclusiveContext checks the SAME original live admission and retains it
// across a synchronous callback. It does not enter the Gate again, authorize a
// command, bind a Store, or grant provider consent. A higher-level owner still
// checks its exact reviewed input and protected control epoch. The callback may
// inspect Gate metadata or nest a current check; no Gate lock is held across it.
// A child context cannot extend the original deadline or revive cancellation.
func (g *Gate) WithExclusiveContext(ctx context.Context, use func() error) error {
	if g == nil || ctx == nil || use == nil {
		return ErrBusy
	}
	o, ok := ctx.Value(exclusiveContextKey{}).(*exclusiveContextOwner)
	if !ok || o == nil || o.gate != g {
		return ErrBusy
	}
	o.mu.Lock()
	if o.closing {
		o.mu.Unlock()
		return ErrBusy
	}
	if err := g.checkExclusiveContext(ctx, o); err != nil {
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
	return errors.Join(err, g.checkExclusiveContext(ctx, o))
}

func (g *Gate) checkExclusiveContext(ctx context.Context, o *exclusiveContextOwner) error {
	if err := o.original.Err(); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.fenced {
		return g.reason
	}
	if !g.exclusive || g.active != 1 {
		return ErrBusy
	}
	return nil
}
