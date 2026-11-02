package app

import (
	"context"
	"errors"

	"github.com/ArtixSx/razvilka/internal/components"
	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/operationgate"
)

// HEV uses the existing exclusive application operation, retained controller
// fleet and configured component owner. No request can choose a state root.
func (a *App) installHEV(ctx context.Context) (components.Result, error) {
	if a == nil || a.Components == nil || a.Store == nil || a.ComponentHistory == nil || a.SelfUpdateFiles == nil || a.Components.StateDir != managedComponentsState {
		return components.Result{}, components.NoMutation(components.ErrRecoveryAuthority)
	}
	held, release, err := a.privateExclusiveOperation(ctx)
	if err != nil {
		return components.Result{}, components.NoMutation(err)
	}
	defer release()
	// Scan before the component manager / writer locks. Every retained actual
	// controller must understand reader5 before its first history is created.
	if err := a.ComponentHistory.CheckWrite(held, components.HEVReleaseReadVersion); err != nil {
		return components.Result{}, components.NoMutation(err)
	}
	control, err := a.Operations.ReviewControlEpoch(held, a.SelfUpdateFiles.ControlRoot)
	if err != nil {
		return components.Result{}, components.NoMutation(err)
	}
	defer control.Close()
	guard := a.hevForwardGuard(a.Store.Get(), control)
	return a.Components.ApplyHEVGuarded(held, guard, control.WithRename)
}

func (a *App) hevForwardGuard(cfg config.Config, control *operationgate.ControlEpochReview) func(context.Context, func() error) error {
	store, files, owner := a.Store, a.SelfUpdateFiles, a.Components
	root := ""
	if files != nil {
		root = files.ControlRoot
	}
	current := func(ctx context.Context) error {
		if store == nil || files == nil || a.Store != store || a.SelfUpdateFiles != files || a.Components != owner || files.ControlRoot != root || control == nil || !control.MatchesControlRoot(root) || cfg.SafeMode {
			return components.ErrRecoveryAuthority
		}
		if err := a.Operations.WithExclusiveContext(ctx, func() error { return nil }); err != nil {
			return err
		}
		if err := control.Current(ctx); err != nil {
			return err
		}
		return a.Store.WithResourceExclusionObservation(ctx, cfg, func(config.EffectiveExclusionSet) error { return nil })
	}
	return func(ctx context.Context, effect func() error) error {
		if effect == nil {
			return components.ErrRecoveryAuthority
		}
		if err := current(ctx); err != nil {
			return err
		}
		// FileTarget separately admits ONLY its final rename through this
		// control owner. Store locks never enclose staging or filesystem IO.
		err := effect()
		return errors.Join(err, current(ctx))
	}
}
