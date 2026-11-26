package app

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/dataplane"
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

// Exercise the actual join entry rather than the context helper. Terminal
// state is deliberately modeled so deleting the original-operation check
// would reach close/release immediately; no native retirement is claimed.
func TestNFQPendingJoinForeignOrCopiedOperationNeverClosesOriginal(t *testing.T) {
	for _, kind := range []string{"foreign-execution", "copied-operation", "copied-runtime", "closed-operation"} {
		t.Run(kind, func(t *testing.T) {
			a, scope, model := nfqwsPacketFixture(t)
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			c, release, err := a.privateExclusiveOperation(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer release()
			cleanup, err := a.Operations.ReviewExclusiveCleanup(c)
			if err != nil {
				t.Fatal(err)
			}
			r := &ManagedNFQWSListRuntime{app: a, manager: a.Dataplane}
			r.self = r
			e := &managedNFQWSListExecution{runtime: r, packetScope: scope, pendingStop: true, retirementKnown: true}
			e.self = e
			r.pending = e
			closed, released := 0, 0
			e.pendingCloseOperation = func() { closed++ }
			e.pendingRelease = func() { released++ }
			op := &managedNFQWSListOperation{execution: e, cleanup: cleanup}
			op.self = op
			op.open.Store(true)
			switch kind {
			case "foreign-execution":
				foreign := &managedNFQWSListExecution{runtime: r, packetScope: scope}
				foreign.self = foreign
				op.execution = foreign
			case "copied-operation":
				copy := &managedNFQWSListOperation{self: op, execution: e, cleanup: cleanup}
				copy.open.Store(true)
				op = copy
			case "copied-runtime":
				r.self = &ManagedNFQWSListRuntime{}
			case "closed-operation":
				op.open.Store(false)
			}
			e.pendingContext = context.WithValue(c, managedNFQWSListOperationKey{}, op)
			if err := r.joinPending(ctx); !errors.Is(err, dataplane.ErrNFQWSScopedOwner) {
				t.Fatalf("foreign operation accepted: %v", err)
			}
			if released != 0 || closed != 0 || model.closed != 0 || r.pending != e || e.pendingContext == nil || e.pendingRelease == nil || e.pendingCloseOperation == nil || r.stopped != nil {
				t.Fatal("unknown join closed or released original owners")
			}
		})
	}
}
