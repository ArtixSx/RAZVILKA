package app

import (
	"context"
	"github.com/ArtixSx/razvilka/internal/components"
)

func (a *App) installMihomo(ctx context.Context) (components.Result, error) {
	if a == nil || a.Components == nil || a.Store == nil || a.ComponentHistory == nil || a.SelfUpdateFiles == nil || a.Components.StateDir != managedComponentsState {
		return components.Result{}, components.NoMutation(components.ErrRecoveryAuthority)
	}
	held, release, err := a.privateExclusiveOperation(ctx)
	if err != nil {
		return components.Result{}, components.NoMutation(err)
	}
	defer release()
	// Admission precedes even creation of the inert artifact cache, so retained
	// old controllers cannot silently ignore this new component format.
	if err := a.ComponentHistory.CheckWrite(held, components.MihomoReleaseReadVersion); err != nil {
		return components.Result{}, components.NoMutation(err)
	}
	control, err := a.Operations.ReviewControlEpoch(held, a.SelfUpdateFiles.ControlRoot)
	if err != nil {
		return components.Result{}, components.NoMutation(err)
	}
	defer control.Close()
	return a.Components.ApplyMihomoGuarded(held, a.hevForwardGuard(a.Store.Get(), control), control.WithRename, control.WithStart)
}
