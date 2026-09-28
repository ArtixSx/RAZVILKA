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

func TestFenceSurvivesOwnerReleaseAndCancellation(t *testing.T) {
	var g Gate
	ctx, cancel := context.WithCancel(context.Background())
	owner, err := g.Exclusive(ctx)
	if err != nil {
		t.Fatal(err)
	}
	g.Fence()
	g.Fence()
	cancel()
	owner()
	owner()
	for _, enter := range []func(context.Context) (func(), error){g.Enter, g.Exclusive} {
		for _, check := range []context.Context{ctx, context.Background()} {
			if _, err := enter(check); !errors.Is(err, ErrRecovery) {
				t.Fatal("fenced admission reopened", err)
			}
		}
	}
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

func TestFenceReasonDistinguishesJournalRecovery(t *testing.T) {
	var private, journal Gate
	private.Fence()
	journal.FenceJournal()
	journal.Fence() // the first reason is kept
	if _, err := private.Enter(context.Background()); !errors.Is(err, ErrRecovery) || errors.Is(err, ErrJournalRecovery) {
		t.Fatalf("private restore fence = %v", err)
	}
	for _, enter := range []func(context.Context) (func(), error){journal.Enter, journal.Exclusive} {
		if _, err := enter(context.Background()); !errors.Is(err, ErrRecovery) || !errors.Is(err, ErrJournalRecovery) {
			t.Fatalf("journal fence = %v", err)
		}
	}
	if s := journal.Snapshot(); !s.Fenced || s.State != "recovery-required" {
		t.Fatalf("snapshot = %+v", s)
	}
}

func TestHolderNamesTheBusyOperation(t *testing.T) {
	var g Gate
	if _, _, ok := g.Holder(); ok {
		t.Fatal("idle gate reported a holder")
	}
	shared, err := g.Enter(WithLabel(context.Background(), "Сбор соединений"))
	if err != nil {
		t.Fatal(err)
	}
	unnamed, err := g.Enter(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if label, _, ok := g.Holder(); !ok || label != "Сбор соединений" {
		t.Fatalf("shared holder = %q %v", label, ok)
	}
	if s := g.Snapshot(); s.Operation != "Сбор соединений" || s.State != "shared" {
		t.Fatalf("snapshot = %+v", s)
	}
	shared()
	unnamed()
	exclusive, err := g.Exclusive(WithLabel(context.Background(), "Автопилот"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := g.Enter(context.Background()); !errors.Is(err, ErrBusy) {
		t.Fatal("exclusive admission was shared", err)
	}
	if label, _, ok := g.Holder(); !ok || label != "Автопилот" {
		t.Fatalf("exclusive holder = %q %v", label, ok)
	}
	exclusive()
	if s := g.Snapshot(); s.Operation != "" || s.State != "idle" {
		t.Fatalf("released holder still shown: %+v", s)
	}
}
