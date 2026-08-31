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

// Gate's zero value is ready to use. Do not copy after first use. Ordinary
// operations may overlap; an exclusive operation starts only when none are
// active. Admission never queues, cancels a worker or forcibly releases it.
type Gate struct {
	mu        sync.Mutex
	active    uint64
	exclusive bool
}

func (*Gate) String() string   { return "[application operation gate]" }
func (*Gate) GoString() string { return "[application operation gate]" }

func (g *Gate) Enter(ctx context.Context) (func(), error)     { return g.enter(ctx, false) }
func (g *Gate) Exclusive(ctx context.Context) (func(), error) { return g.enter(ctx, true) }

func (g *Gate) enter(ctx context.Context, exclusive bool) (func(), error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if g.exclusive || exclusive && g.active != 0 {
		return nil, ErrBusy
	}
	g.active++
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
