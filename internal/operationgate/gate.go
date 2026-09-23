// Package operationgate excludes a short, multi-store restore from cooperating
// HTTP and background operations. It is in-process admission control, not a
// durable journal, file lock, transaction or replacement for Store sessions.
package operationgate

import (
	"context"
	"errors"
	"sync"
)

var ErrBusy = errors.New("application operations are busy")
var ErrRecovery = errors.New("application operations require private restore recovery")
var ErrChanged = errors.New("application operations changed during observation")

// Gate's zero value is ready to use. Do not copy after first use. Ordinary
// operations may overlap; an exclusive operation starts only when none are
// active. Admission never queues, cancels a worker or forcibly releases it.
type Gate struct {
	mu         sync.Mutex
	active     uint64
	exclusive  bool
	fenced     bool
	generation uint64
}

func (*Gate) String() string   { return "[application operation gate]" }
func (*Gate) GoString() string { return "[application operation gate]" }

func (g *Gate) Enter(ctx context.Context) (func(), error)     { return g.enter(ctx, false) }
func (g *Gate) Exclusive(ctx context.Context) (func(), error) { return g.enter(ctx, true) }

// Fence permanently refuses new admissions on this instance. Call while still
// owning exclusive admission after an uncertain restore. Only a fresh startup,
// after durable journal recovery and Store reload, can create a new open Gate.
func (g *Gate) Fence() {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.fenced = true
}

func (g *Gate) enter(ctx context.Context, exclusive bool) (func(), error) {
	return g.enterAfter(ctx, exclusive, nil, true)
}

// IdleGeneration and ExclusiveAfter support read-only preparation outside the
// gate. Any intervening admission invalidates the observation, including one
// that has already completed. They never authorize replay of a network change.
func (g *Gate) IdleGeneration() (uint64, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.generation, g.active == 0 && !g.fenced
}

func (g *Gate) ExclusiveAfter(ctx context.Context, generation uint64) (func(), error) {
	return g.enterAfter(ctx, true, &generation, true)
}

// ObserveExclusive protects a short memory-only capture/publication. No Store
// writes, probing or external commands are allowed under this lease.
func (g *Gate) ObserveExclusive(ctx context.Context, generation *uint64) (func(), error) {
	return g.enterAfter(ctx, true, generation, false)
}

func (g *Gate) enterAfter(ctx context.Context, exclusive bool, generation *uint64, advance bool) (func(), error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.fenced {
		return nil, ErrRecovery
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if generation != nil && g.generation != *generation {
		return nil, ErrChanged
	}
	if g.exclusive || exclusive && g.active != 0 {
		return nil, ErrBusy
	}
	g.active++
	if advance {
		g.generation++
	}
	g.exclusive = exclusive
	var once sync.Once
	return func() {
		once.Do(func() {
			g.mu.Lock()
			defer g.mu.Unlock()
			g.active--
			if exclusive {
				g.exclusive = false
			}
		})
	}, nil
}
