package main

import (
	"context"
	"time"

	"github.com/ArtixSx/razvilka/internal/app"
	"github.com/ArtixSx/razvilka/internal/operationgate"
	"github.com/ArtixSx/razvilka/internal/strategylab"
)

// Call once before background workers and HTTP. The genuine component receipt
// and existing control owner supply installation evidence; startup creates no
// candidate, selection, validation session, scope permission or process effect.
// A missing/changed generation remains unavailable until genuinely configured.
func configureManagedNFQCompatibility(parent context.Context, a *app.App) (*operationgate.ControlEpochReview, error) {
	if parent == nil || a == nil || a.StrategyLab == nil || a.Components == nil || a.SelfUpdateFiles == nil {
		return nil, strategylab.ErrSelectedCandidateChanged
	}
	ctx, cancel := context.WithTimeout(parent, 15*time.Second)
	defer cancel()
	ctx, release, err := a.Operations.ExclusiveContext(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	return a.ConfigureManagedNFQCompatibility(ctx)
}
