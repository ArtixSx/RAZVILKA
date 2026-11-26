package app

import (
	"context"
	"time"

	"github.com/ArtixSx/razvilka/internal/dataplane"
)

const managedNFQCleanupBudget = 120 * time.Second

// Called only for an already retained original cleanup operation. Its values
// remain original even after forward cancellation; every actual owner check
// still runs. The caller supplies a fresh finite budget for the whole join.
// This cleanup bound is independent of the immutable 15s Start/transfer seal.
func managedNFQCleanupContext(parent, original context.Context) (context.Context, context.CancelFunc, error) {
	if parent == nil || original == nil || parent.Err() != nil {
		return nil, nil, dataplane.ErrNFQWSScopedOwner
	}
	deadline, finite := parent.Deadline()
	if !finite || !time.Now().Before(deadline) {
		return nil, nil, dataplane.ErrNFQWSScopedOwner
	}
	if ceiling := time.Now().Add(managedNFQCleanupBudget); deadline.After(ceiling) {
		deadline = ceiling
	}
	c, cancel := context.WithDeadline(context.WithoutCancel(original), deadline)
	return c, cancel, nil
}
