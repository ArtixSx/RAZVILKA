package operationgate

import (
	"context"
	"errors"
	"testing"
	"time"
)

type cleanupDeadlineWithoutDelivery struct {
	context.Context
	deadline time.Time
	bounded  bool
	err      error
	errCalls int
}

func (c *cleanupDeadlineWithoutDelivery) Deadline() (time.Time, bool) { return c.deadline, c.bounded }
func (c *cleanupDeadlineWithoutDelivery) Err() error                  { c.errCalls++; return c.err }

func TestExclusiveCleanupExpiredDeadlineBeforeContextDelivery(t *testing.T) {
	var g Gate
	owner, release, err := g.ExclusiveContext(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	r, err := g.ReviewExclusiveCleanup(owner)
	if err != nil {
		t.Fatal(err)
	}
	called := 0
	expired := &cleanupDeadlineWithoutDelivery{Context: context.Background(), deadline: time.Now().Add(-time.Second), bounded: true}
	err = r.WithCurrent(expired, func() error { called++; return nil })
	if !errors.Is(err, ErrBusy) || !errors.Is(err, context.DeadlineExceeded) || called != 0 || expired.errCalls != 1 {
		t.Fatalf("lost cause or invoked action: %v calls=%d errReads=%d", err, called, expired.errCalls)
	}
	// Expiry refused only that attempted use, without releasing the held owner.
	live, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := r.WithCurrent(live, func() error { called++; return nil }); err != nil || called != 1 {
		t.Fatalf("owner altered: %v calls=%d", err, called)
	}
}

func TestExclusiveCleanupLiveBusyAndCallerErrorsUnchanged(t *testing.T) {
	var g Gate
	owner, release, err := g.ExclusiveContext(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	r, err := g.ReviewExclusiveCleanup(owner)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name         string
		bounded      bool
		caller, want error
	}{
		{"unbounded", false, nil, ErrBusy}, {"canceled", true, context.Canceled, context.Canceled}, {"delivered-deadline", true, context.DeadlineExceeded, context.DeadlineExceeded},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := &cleanupDeadlineWithoutDelivery{Context: context.Background(), deadline: time.Now().Add(-time.Second), bounded: tc.bounded, err: tc.caller}
			if got := r.WithCurrent(ctx, func() error { t.Fatal("refused callback ran"); return nil }); got != tc.want || ctx.errCalls != 1 {
				t.Fatalf("changed existing result %v reads=%d", got, ctx.errCalls)
			}
		})
	}
	release() // Genuine stale owner, not a fabricated gate count.
	live, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	got := r.WithCurrent(live, func() error { t.Fatal("released owner ran"); return nil })
	if got != ErrBusy || errors.Is(got, context.DeadlineExceeded) {
		t.Fatalf("live busy reclassified: %v", got)
	}
}
