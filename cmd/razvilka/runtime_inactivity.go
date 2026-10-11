package main

import (
	"context"
	"errors"
	"time"

	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/installpath"
	"github.com/ArtixSx/razvilka/internal/netidentity"
	"github.com/ArtixSx/razvilka/internal/startuptools"
)

// Helper ownership ends only after its original complete Deactivate/proof
// operation. No Verify call reacquires tools, replaces the provider or extends
// the original caller deadline.
func selfUpdateRuntimeManagerBound(ctx context.Context) (*dataplane.Manager, func() error, error) {
	if ctx == nil || ctx.Err() != nil {
		return nil, nil, dataplane.ErrRuntimeInactivity
	}
	if deadline, finite := ctx.Deadline(); !finite || !time.Now().Before(deadline) {
		return nil, nil, dataplane.ErrRuntimeInactivity
	}
	manager, err := selfUpdateRuntimeManager()
	if err != nil {
		return nil, nil, err
	}
	provider, err := netidentity.NewReviewedStockNC1812Provider(ctx)
	if err != nil {
		return nil, nil, err
	}
	tools, err := startuptools.AcquireReviewedStockNC1812(ctx, provider)
	if err != nil {
		return nil, nil, err
	}
	closeRefused := func(cause error) (*dataplane.Manager, func() error, error) {
		return nil, nil, errors.Join(cause, tools.Close())
	}
	backendTools, err := tools.InventoryTools()
	if err != nil {
		return closeRefused(err)
	}
	inventory, err := dataplane.NewReviewedStockNC1812BackendInventory(provider, backendTools)
	if err != nil {
		return closeRefused(err)
	}
	if err := manager.BindRuntimeInactivitySources(ctx, provider, inventory, selfUpdateDefaultPath(installpath.State+"/dns/state.json")); err != nil {
		return closeRefused(err)
	}
	return manager, tools.Close, nil
}
