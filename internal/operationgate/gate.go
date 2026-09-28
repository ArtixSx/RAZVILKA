// Package operationgate excludes a short, multi-store restore from cooperating
// HTTP and background operations. It is in-process admission control, not a
// durable journal, file lock, transaction or replacement for Store sessions.
package operationgate

import (
	"context"
	"errors"
	"sync"
	"time"
)

var ErrBusy = errors.New("application operations are busy")
var ErrRecovery = errors.New("application operations require private restore recovery")
var ErrChanged = errors.New("application operations changed during observation")

// ErrJournalRecovery is the fence reason when startup found an unfinished or
// unverified network transaction. It matches ErrRecovery, but unlike a private
// restore a restart does not settle it: an operator must review the journal.
var ErrJournalRecovery error = journalRecoveryError{}

type journalRecoveryError struct{}

func (journalRecoveryError) Error() string {
	return "application operations require network transaction journal recovery"
}
func (journalRecoveryError) Is(target error) bool { return target == ErrRecovery }

// Gate's zero value is ready to use. Do not copy after first use. Ordinary
// operations may overlap; an exclusive operation starts only when none are
// active. Admission never queues, cancels a worker or forcibly releases it.
type Gate struct {
	mu         sync.Mutex
	active     uint64
	exclusive  bool
	fenced     bool
	reason     error // why the gate is fenced; the first reason is kept
	generation uint64
	holders    map[uint64]holder // admitted operations, for the busy explanation
	nextHolder uint64
}

// holder describes one admitted operation. It is presentation only: it grants
// nothing and is never used to decide admission.
type holder struct {
	label     string
	since     time.Time
	exclusive bool
}

type labelKey struct{}

// WithLabel names the operation that ctx will enter the gate for, in words an
// operator understands. The label is shown when another request is refused as
// busy; it must not contain addresses, keys or other private data.
func WithLabel(ctx context.Context, label string) context.Context {
	return context.WithValue(ctx, labelKey{}, label)
}

func labelOf(ctx context.Context) string {
	label, _ := ctx.Value(labelKey{}).(string)
	return label
}

// Holder reports the operation that currently makes the gate busy: the
// exclusive holder, otherwise the longest-running labeled shared one.
func (g *Gate) Holder() (label string, since time.Time, ok bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.holderLocked()
}

func (g *Gate) holderLocked() (label string, since time.Time, ok bool) {
	for _, h := range g.holders {
		if h.exclusive {
			return h.label, h.since, true
		}
		if h.label != "" && (!ok || h.since.Before(since)) {
			label, since, ok = h.label, h.since, true
		}
	}
	return label, since, ok
}

func (*Gate) String() string   { return "[application operation gate]" }
func (*Gate) GoString() string { return "[application operation gate]" }

func (g *Gate) Enter(ctx context.Context) (func(), error)     { return g.enter(ctx, false) }
func (g *Gate) Exclusive(ctx context.Context) (func(), error) { return g.enter(ctx, true) }

// Fence permanently refuses new admissions on this instance. Call while still
// owning exclusive admission after an uncertain restore. Only a fresh startup,
// after durable journal recovery and Store reload, can create a new open Gate.
func (g *Gate) Fence() { g.fence(ErrRecovery) }

// FenceJournal fences like Fence and records that the network transaction
// journal, not a private restore, requires review.
func (g *Gate) FenceJournal() { g.fence(ErrJournalRecovery) }

func (g *Gate) fence(reason error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if !g.fenced {
		g.reason = reason
	}
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
		return nil, g.reason
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
	if g.holders == nil {
		g.holders = map[uint64]holder{}
	}
	g.nextHolder++
	id := g.nextHolder
	g.holders[id] = holder{label: labelOf(ctx), since: time.Now(), exclusive: exclusive}
	var once sync.Once
	return func() {
		once.Do(func() {
			g.mu.Lock()
			defer g.mu.Unlock()
			g.active--
			if exclusive {
				g.exclusive = false
			}
			delete(g.holders, id)
		})
	}, nil
}
