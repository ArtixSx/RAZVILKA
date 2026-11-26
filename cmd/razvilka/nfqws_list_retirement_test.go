package main

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestManagedListRetirementRetainsOriginalUntilFullCleanupSucceeds(t *testing.T) {
	var previous context.Context
	var contexts []context.Context
	waits := []time.Duration{}
	// This closure stands for the original retained runtime/control owners.
	// A failed owner is retried; neither the context nor elapsed time is success.
	original := new(int)
	owner := original
	retainManagedListRetirementWithWait(func(ctx context.Context) error {
		if owner != original {
			t.Fatal("original owner replaced")
		}
		if previous != nil && previous.Err() != context.Canceled {
			t.Fatal("previous attempt context retained")
		}
		deadline, ok := ctx.Deadline()
		want := 120 * time.Second
		if len(contexts) == 0 {
			want = 90 * time.Second
		}
		remaining := time.Until(deadline)
		if !ok || remaining > want || remaining < want-time.Second {
			t.Fatalf("cleanup budget %s want %s", remaining, want)
		}
		previous = ctx
		contexts = append(contexts, ctx)
		*owner++
		if *owner < 4 {
			return errors.New("original cleanup remains unconfirmed")
		}
		return nil
	}, func(delay time.Duration) {
		if previous.Err() != context.Canceled {
			t.Fatal("failed attempt not canceled before retry wait")
		}
		waits = append(waits, delay)
	})
	if *original != 4 || len(waits) != 3 || waits[0] != time.Second || waits[1] != 2*time.Second || waits[2] != 4*time.Second {
		t.Fatalf("original retry sequence calls=%d waits=%v", *original, waits)
	}
	for _, ctx := range contexts {
		if ctx.Err() != context.Canceled {
			t.Fatal("attempt context leaked after completion")
		}
	}
}
