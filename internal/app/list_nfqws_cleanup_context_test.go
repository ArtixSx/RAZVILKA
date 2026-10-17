package app

import (
	"context"
	"testing"
	"time"
)

func TestNFQCleanupUsesFiniteCallerBudgetAndOriginalExpiredOperation(t *testing.T) {
	type key struct{}
	originalOwner := new(int)
	original, cancelOriginal := context.WithCancel(context.WithValue(context.Background(), key{}, originalOwner))
	cancelOriginal()
	for _, budget := range []time.Duration{time.Second, 90 * time.Second, 3 * time.Minute} {
		parent, cancelParent := context.WithTimeout(context.Background(), budget)
		c, cancel, err := managedNFQCleanupContext(parent, original)
		if err != nil {
			t.Fatal(err)
		}
		deadline, finite := c.Deadline()
		parentDeadline, _ := parent.Deadline()
		remaining := time.Until(deadline)
		if !finite || deadline.After(parentDeadline) || remaining > 120*time.Second || c.Value(key{}) != originalOwner || c.Err() != nil {
			t.Fatal("cleanup lost original operation or finite caller bound")
		}
		if budget >= 90*time.Second && remaining < 89*time.Second {
			t.Fatal("cleanup retained activation cap; slow NFQ proof leaves no LAN budget", remaining)
		}
		cancelParent()
		if c.Err() != nil {
			t.Fatal("admitted cleanup detached original owner on caller cancellation")
		}
		cancel()
		if c.Err() != context.Canceled {
			t.Fatal("cleanup context did not release")
		}
	}
	for _, parent := range []context.Context{nil, context.Background(), original} {
		if c, cancel, err := managedNFQCleanupContext(parent, original); err == nil || c != nil || cancel != nil {
			t.Fatal("missing/exhausted caller budget admitted cleanup")
		}
	}
}
