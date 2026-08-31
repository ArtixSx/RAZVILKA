package operationgate

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
)

func TestSharedExclusiveAndIdempotentRelease(t *testing.T) {
	var g Gate
	ctx := context.Background()
	a, err := g.Enter(ctx)
	if err != nil {
		t.Fatal(err)
	}
	b, err := g.Enter(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := g.Exclusive(ctx); !errors.Is(err, ErrBusy) {
		t.Fatal("exclusive overlapped readers")
	}
	a()
	a()
	if _, err := g.Exclusive(ctx); !errors.Is(err, ErrBusy) {
		t.Fatal("double release unlocked another reader")
	}
	b()
	exclusive, err := g.Exclusive(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := g.Enter(ctx); !errors.Is(err, ErrBusy) {
		t.Fatal("shared overlapped exclusive")
	}
	if _, err := g.Exclusive(ctx); !errors.Is(err, ErrBusy) {
		t.Fatal("two restores overlapped")
	}
	exclusive()
	exclusive()
	last, err := g.Enter(ctx)
	if err != nil {
		t.Fatal(err)
	}
	last()
}

func TestCancellationDoesNotReleaseAnActiveOperation(t *testing.T) {
	var g Gate
	ctx, cancel := context.WithCancel(context.Background())
	release, err := g.Enter(ctx)
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	if _, err := g.Exclusive(context.Background()); !errors.Is(err, ErrBusy) {
		t.Fatal("cancellation released ownership before cleanup")
	}
	release()
	for _, enter := range []func(context.Context) (func(), error){g.Enter, g.Exclusive} {
		if _, err := enter(ctx); !errors.Is(err, context.Canceled) {
			t.Fatal("canceled work admitted")
		}
	}
	x, err := g.Exclusive(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	x()
}

func TestParallelAdmissionNeverOverlapsExclusive(t *testing.T) {
	var g Gate
	var shared, exclusive atomic.Int64
	var bad atomic.Bool
	var wg sync.WaitGroup
	for n := 0; n < 20; n++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 500; i++ {
				isExclusive := (i+n)%3 == 0
				enter := g.Enter
				if isExclusive {
					enter = g.Exclusive
				}
				release, err := enter(context.Background())
				if errors.Is(err, ErrBusy) {
					continue
				}
				if err != nil {
					bad.Store(true)
					continue
				}
				if isExclusive {
					if exclusive.Add(1) != 1 || shared.Load() != 0 {
						bad.Store(true)
					}
					exclusive.Add(-1)
				} else {
					shared.Add(1)
					if exclusive.Load() != 0 {
						bad.Store(true)
					}
					shared.Add(-1)
				}
				release()
			}
		}()
	}
	wg.Wait()
	if bad.Load() {
		t.Fatal("admission was not exclusive")
	}
	release, err := g.Exclusive(context.Background())
	if err != nil {
		t.Fatal("leaked admission", err)
	}
	release()
}
