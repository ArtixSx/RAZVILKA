package main

import (
	"context"
	"log"
	"time"

	"github.com/ArtixSx/razvilka/internal/app"
	"github.com/ArtixSx/razvilka/internal/dataplane"
)

// The same ordinary App owns construction and every fresh operation. Startup
// observes the fixed stock platform/tools; it never starts a selected route.
func configureManagedNFQList(parent context.Context, a *app.App) (*app.ManagedNFQWSListRuntime, error) {
	if parent == nil || a == nil {
		return nil, dataplane.ErrNFQWSScopedOwner
	}
	ctx, cancel := context.WithTimeout(parent, 15*time.Second)
	defer cancel()
	return a.ConfigureReviewedStockNFQWSList(ctx, parent)
}

func configureManagedXraySelectedTCPList(parent context.Context, a *app.App) (*app.ManagedXraySelectedTCPListRuntime, error) {
	if parent == nil || a == nil {
		return nil, dataplane.ErrXrayOperationOwner
	}
	ctx, cancel := context.WithTimeout(parent, 15*time.Second)
	defer cancel()
	return a.ConfigureReviewedStockXraySelectedTCPList(ctx, parent)
}

func configureManagedWGList(parent context.Context, a *app.App) (*app.ManagedWGListRuntime, error) {
	if parent == nil || a == nil {
		return nil, dataplane.ErrWGOperationOwner
	}
	ctx, cancel := context.WithTimeout(parent, 15*time.Second)
	defer cancel()
	return a.ConfigureReviewedStockWGList(ctx, parent)
}

// Returning from main destroys the original owners and held files even when
// their child is detached. Every unsuccessful join therefore keeps this process
// alive. The init script reports a timed-out stop and keeps its PID file; it does
// not turn that timeout into a cleanup confirmation.
func retainManagedListRetirement(closeAttempt func(context.Context) error) {
	retainManagedListRetirementWithWait(closeAttempt, time.Sleep)
}

// A cleanup attempt includes every retained runtime and the final startup and
// control owners. Complete fresh kernel inventories can exceed the activation
// handshake's 15s; these independent cleanup budgets grant no forward admission.
// Increase only after a failed attempt, while retaining the same original owner.
func retainManagedListRetirementWithWait(closeAttempt func(context.Context) error, wait func(time.Duration)) {
	retryDelay := time.Second
	attemptBudget := 90 * time.Second
	for {
		ctx, cancel := context.WithTimeout(context.Background(), attemptBudget)
		err := closeAttempt(ctx)
		cancel()
		if err == nil {
			return
		}
		log.Print("Managed list retirement remains unconfirmed; retaining original owners for another cleanup attempt")
		wait(retryDelay)
		attemptBudget = 120 * time.Second
		if retryDelay < 15*time.Second {
			retryDelay *= 2
			if retryDelay > 15*time.Second {
				retryDelay = 15 * time.Second
			}
		}
	}
}
