package operationgate

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestExclusiveCleanupRetainsKnownLifetimeWithoutForwardAuthority(t *testing.T) {
	var g Gate
	raw, cancel := context.WithCancel(context.Background())
	ctx, release, err := g.ExclusiveContext(raw)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	cleanup, err := g.ReviewExclusiveCleanup(ctx)
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	g.FenceJournal()
	if _, err := g.ReviewExclusiveCleanup(context.WithoutCancel(ctx)); !errors.Is(err, context.Canceled) {
		t.Fatal("late cleanup issued", err)
	}
	bounded, cancelCleanup := context.WithTimeout(context.Background(), time.Second)
	defer cancelCleanup()
	if err := cleanup.WithCurrent(bounded, func() error {
		if err := g.WithExclusiveContext(bounded, func() error { t.Fatal("cleanup minted forward context"); return nil }); !errors.Is(err, ErrBusy) {
			t.Fatal(err)
		}
		if err := g.WithExclusiveContext(context.WithoutCancel(ctx), func() error { t.Fatal("expired forward revived"); return nil }); !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
		if g.Snapshot().Active != 1 {
			t.Fatal("known owner released before join")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	release()
	if err := cleanup.WithCurrent(bounded, func() error { t.Fatal("released cleanup revived"); return nil }); !errors.Is(err, ErrBusy) {
		t.Fatal(err)
	}
}

func TestExclusiveCleanupRejectsRawZeroAndUnboundedContext(t *testing.T) {
	var g Gate
	if _, err := g.ReviewExclusiveCleanup(context.Background()); !errors.Is(err, ErrBusy) {
		t.Fatal(err)
	}
	ctx, release, err := g.ExclusiveContext(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	r, err := g.ReviewExclusiveCleanup(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.WithCurrent(context.Background(), func() error { t.Fatal("unbounded cleanup"); return nil }); !errors.Is(err, ErrBusy) {
		t.Fatal(err)
	}
	bounded, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	copy := &ExclusiveCleanupReview{self: r.self, owner: r.owner}
	if err := copy.WithCurrent(bounded, func() error { t.Fatal("copied cleanup"); return nil }); !errors.Is(err, ErrBusy) {
		t.Fatal(err)
	}
	if err := (&ExclusiveCleanupReview{}).WithCurrent(bounded, func() error { t.Fatal("zero cleanup"); return nil }); !errors.Is(err, ErrBusy) {
		t.Fatal(err)
	}
	cancel()
	if err := r.WithCurrent(bounded, func() error { t.Fatal("canceled cleanup"); return nil }); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}
