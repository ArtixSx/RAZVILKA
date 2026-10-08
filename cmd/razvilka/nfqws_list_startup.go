package main

import (
	"context"
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
