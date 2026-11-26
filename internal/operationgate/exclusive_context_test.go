package operationgate

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

func TestExclusiveContextOriginalOwnerOnly(t *testing.T) {
	var g, foreign Gate
	raw := WithLabel(context.Background(), "review")
	ctx, release, err := g.ExclusiveContext(raw)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	for _, c := range []context.Context{raw, context.Background()} {
		if err := g.WithExclusiveContext(c, func() error { t.Fatal("unowned use"); return nil }); !errors.Is(err, ErrBusy) {
			t.Fatal(err)
		}
	}
	if err := foreign.WithExclusiveContext(ctx, func() error { t.Fatal("foreign use"); return nil }); !errors.Is(err, ErrBusy) {
		t.Fatal(err)
	}
	if _, _, err := g.ExclusiveContext(ctx); !errors.Is(err, ErrBusy) {
		t.Fatal("reentrant admission", err)
	}
	if err := g.WithExclusiveContext(ctx, func() error {
		if label, _, ok := g.Holder(); !ok || label != "review" {
			t.Fatal("original holder lost")
		}
		_ = g.Snapshot()
		return g.WithExclusiveContext(ctx, func() error { return nil })
	}); err != nil {
		t.Fatal(err)
	}
	release()
	release()
	if err := g.WithExclusiveContext(ctx, func() error { t.Fatal("released owner"); return nil }); !errors.Is(err, ErrBusy) {
		t.Fatal(err)
	}
	// A later actual admission cannot revive the old context.
	next, closeNext, err := g.ExclusiveContext(raw)
	if err != nil {
		t.Fatal(err)
	}
	defer closeNext()
	if err := g.WithExclusiveContext(ctx, func() error { t.Fatal("old owner revived"); return nil }); !errors.Is(err, ErrBusy) {
		t.Fatal(err)
	}
	if err := g.WithExclusiveContext(next, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
}

func TestExclusiveContextOrdinaryExclusiveAndOriginalDeadlineCannotIssue(t *testing.T) {
	var g Gate
	release, err := g.Exclusive(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := g.WithExclusiveContext(context.Background(), func() error { t.Fatal("plain exclusive became capability"); return nil }); !errors.Is(err, ErrBusy) {
		t.Fatal(err)
	}
	release()
	raw, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	ctx, release, err := g.ExclusiveContext(raw)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	<-raw.Done()
	if err := g.WithExclusiveContext(context.WithoutCancel(ctx), func() error { t.Fatal("original deadline extended"); return nil }); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
}

func TestExclusiveContextCancellationFenceAndClosing(t *testing.T) {
	for _, stop := range []string{"cancel", "fence", "deadline"} {
		t.Run(stop, func(t *testing.T) {
			var g Gate
			raw, cancel := context.WithCancel(context.Background())
			defer cancel()
			ctx, release, err := g.ExclusiveContext(raw)
			if err != nil {
				t.Fatal(err)
			}
			defer release()
			check := context.WithoutCancel(ctx)
			want := context.Canceled
			err = g.WithExclusiveContext(check, func() error {
				switch stop {
				case "cancel":
					cancel()
				case "fence":
					g.FenceJournal()
					want = ErrJournalRecovery
				case "deadline":
					var closeCheck context.CancelFunc
					check, closeCheck = context.WithDeadline(ctx, time.Now().Add(-time.Second))
					defer closeCheck()
					// The supplied child context is independently checked.
					if e := g.WithExclusiveContext(check, func() error { t.Fatal("expired child"); return nil }); !errors.Is(e, context.DeadlineExceeded) {
						t.Fatal(e)
					}
					cancel()
				}
				return nil
			})
			if !errors.Is(err, want) {
				t.Fatal("closing check", err)
			}
			if err := g.WithExclusiveContext(context.WithoutCancel(ctx), func() error { t.Fatal("revived canceled/fenced owner"); return nil }); !errors.Is(err, want) {
				t.Fatal(err)
			}
			if g.Snapshot().Active != 1 {
				t.Fatal("cancel/fence released before owner cleanup")
			}
		})
	}
}

func TestExclusiveContextReleaseJoinsUseAndRefusesNestedLateUse(t *testing.T) {
	var g Gate
	ctx, release, err := g.ExclusiveContext(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	entered, finish, used, closed := make(chan struct{}), make(chan struct{}), make(chan error, 1), make(chan struct{})
	go func() { used <- g.WithExclusiveContext(ctx, func() error { close(entered); <-finish; return nil }) }()
	<-entered
	go func() { release(); close(closed) }()
	o := ctx.Value(exclusiveContextKey{}).(*exclusiveContextOwner)
	// Synchronize on the actual closing state; a timer is only a test deadline.
	until := time.After(2 * time.Second)
	for {
		o.mu.Lock()
		closing := o.closing
		o.mu.Unlock()
		if closing {
			break
		}
		select {
		case <-until:
			t.Fatal("release did not start")
		default:
			time.Sleep(time.Millisecond)
		}
	}
	if err := g.WithExclusiveContext(ctx, func() error { t.Fatal("late use"); return nil }); !errors.Is(err, ErrBusy) {
		t.Fatal(err)
	}
	if _, err := g.Enter(context.Background()); !errors.Is(err, ErrBusy) {
		t.Fatal("released before join", err)
	}
	select {
	case <-closed:
		t.Fatal("release returned before use")
	default:
	}
	close(finish)
	if err := <-used; err != nil {
		t.Fatal(err)
	}
	<-closed
	if g.Snapshot().Active != 0 {
		t.Fatal("owner not released")
	}
}

func TestExclusiveContextPanicJoinsAndIdempotentConcurrentRelease(t *testing.T) {
	var g Gate
	ctx, release, err := g.ExclusiveContext(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("panic swallowed")
			}
		}()
		_ = g.WithExclusiveContext(ctx, func() error { panic("test") })
	}()
	var joined sync.WaitGroup
	for range 8 {
		joined.Add(1)
		go func() { defer joined.Done(); release() }()
	}
	joined.Wait()
	if g.Snapshot().Active != 0 {
		t.Fatal("panic retained stale use")
	}
}
