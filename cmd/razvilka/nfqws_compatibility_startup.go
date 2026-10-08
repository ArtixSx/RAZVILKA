package main

import (
	"context"
	"errors"
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
	control, err := a.Operations.ReviewControlEpoch(ctx, a.SelfUpdateFiles.ControlRoot)
	if err != nil {
		return nil, err
	}
	keepControl := false
	defer func() {
		if !keepControl {
			_ = control.Close()
		}
	}()
	lease, err := a.Components.AcquireCurrentManagedNFQWSRuntime(ctx)
	if err != nil {
		return nil, err
	}
	provider, validator, buildErr := strategylab.NewManagedSupervisedCompatibilityProvider(ctx, a.StrategyLab, lease, control, a.SelfUpdateFiles.ControlRoot)
	// No validation/process is run during configuration. The bootstrap lease
	// can close here; every real validation later reacquires the current lease.
	closeErr := lease.Close()
	if buildErr != nil || closeErr != nil || provider == nil || validator.Provider != provider {
		return nil, errors.Join(strategylab.ErrSelectedCandidateChanged, buildErr, closeErr)
	}
	a.StrategyLab.Validator = validator
	keepControl = true
	return control, nil
}
