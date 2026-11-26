package app

import (
	"context"
	"github.com/ArtixSx/razvilka/internal/backendprofile"
	"github.com/ArtixSx/razvilka/internal/components"
)

func (a *App) installMihomo(ctx context.Context) (components.Result, error) {
	return a.applyMihomoPackage(ctx, false)
}

func (a *App) updateMihomo(ctx context.Context) (components.Result, error) {
	return a.applyMihomoPackage(ctx, true)
}

func (a *App) applyMihomoPackage(ctx context.Context, replace bool) (components.Result, error) {
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
	guard := a.hevForwardGuard(a.Store.Get(), control)
	if !replace {
		return a.Components.ApplyMihomoGuarded(held, guard, control.WithRename, control.WithStart)
	}
	a.mihomoProbe.mu.Lock()
	adapter := a.mihomoProbe.adapter
	a.mihomoProbe.mu.Unlock()
	if a.Dataplane == nil || adapter == nil || !adapter.RegisteredWith(a.Dataplane) {
		return components.Result{}, components.NoMutation(components.ErrRecoveryAuthority)
	}
	inactive := func(c context.Context, review *components.MihomoReplacementReview) error {
		return guard(c, func() error {
			return a.Dataplane.VerifyMihomoReplacementInactive(c, adapter, review)
		})
	}
	return a.Components.ApplyMihomoReplacementGuarded(held, guard, control.WithRename, control.WithStart, inactive)
}

func (a *App) validateMihomo(ctx context.Context, source string, options backendprofile.MihomoOptions, review string) (components.MihomoNativeValidation, error) {
	if a == nil || a.Components == nil || a.Store == nil || a.ComponentHistory == nil || a.SelfUpdateFiles == nil || a.Components.StateDir != managedComponentsState {
		return components.MihomoNativeValidation{}, components.ErrRecoveryAuthority
	}
	held, release, err := a.privateExclusiveOperation(ctx)
	if err != nil {
		return components.MihomoNativeValidation{}, err
	}
	defer release()
	if err := a.ComponentHistory.CheckReadable(held); err != nil {
		return components.MihomoNativeValidation{}, err
	}
	control, err := a.Operations.ReviewControlEpoch(held, a.SelfUpdateFiles.ControlRoot)
	if err != nil {
		return components.MihomoNativeValidation{}, err
	}
	defer control.Close()
	return a.Components.ValidateMihomoProfileGuarded(held, source, options, review, a.hevForwardGuard(a.Store.Get(), control), control.WithStart)
}
