package dataplane

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
)

// A finite bootstrap carrier retains the actual issuing context, including its
// private Gate values. It cannot be built from saved intent or handed to the
// active receiver as a replacement for the original Commit ACK.
type syntheticBaselineExecutionPhase struct {
	self      *syntheticBaselineExecutionPhase
	binding   *SyntheticDNSExecutionBinding
	ctx       context.Context
	cancel    context.CancelFunc
	stopScope func() bool
	barrier   sync.RWMutex
	closed    atomic.Bool
	joined    chan struct{}
}

func newSyntheticBaselineExecutionPhase(ctx context.Context, b *SyntheticDNSExecutionBinding) (*syntheticBaselineExecutionPhase, error) {
	if b == nil || b.self != b || ctx == nil || ctx.Value(syntheticExecutionRegistrarKey{}) != b.scope {
		return nil, ErrSyntheticBaselineTransition
	}
	if err := b.Current(ctx); err != nil {
		return nil, err
	}
	life, cancel := context.WithCancel(ctx)
	p := &syntheticBaselineExecutionPhase{binding: b, ctx: life, cancel: cancel, joined: make(chan struct{})}
	p.self = p
	p.stopScope = context.AfterFunc(b.scope.ctx, cancel)
	return p, nil
}

// The child inherits ONLY the original phase's authority values. Request
// cancellation and its earlier deadline still bound the complete admission,
// upstream, reservation and publication call. No new Gate admission is issued.
func (p *syntheticBaselineExecutionPhase) WithRequest(request context.Context, use func(context.Context) error) error {
	if p == nil || p.self != p || request == nil || use == nil || p.closed.Load() {
		return ErrSyntheticBaselineTransition
	}
	p.barrier.RLock()
	defer p.barrier.RUnlock()
	if p.closed.Load() || p.ctx.Err() != nil || request.Err() != nil {
		return errors.Join(ErrSyntheticBaselineTransition, p.ctx.Err(), request.Err())
	}
	deadline, finite := p.ctx.Deadline()
	if !finite {
		return ErrSyntheticBaselineTransition
	}
	if earlier, bounded := request.Deadline(); bounded && earlier.Before(deadline) {
		deadline = earlier
	}
	held, cancel := context.WithDeadline(p.ctx, deadline)
	defer cancel()
	stop := context.AfterFunc(request, cancel)
	defer stop()
	if request.Err() != nil {
		cancel()
	}
	if err := p.binding.Current(held); err != nil {
		return err
	}
	err := use(held)
	return errors.Join(err, held.Err(), request.Err(), p.binding.Current(held))
}

// Revoke BEFORE waiting for borrowers. CORE must join this carrier before
// releasing its original operation, and replace it only after receiver ACK.
// This join says nothing about baseline/capture removal or retained aliases.
func (p *syntheticBaselineExecutionPhase) Close() error {
	if p == nil || p.self != p {
		return ErrSyntheticBaselineTransition
	}
	if p.closed.CompareAndSwap(false, true) {
		p.cancel()
		p.stopScope()
		p.barrier.Lock()
		close(p.joined)
		p.barrier.Unlock()
	} else {
		<-p.joined
	}
	return nil
}
