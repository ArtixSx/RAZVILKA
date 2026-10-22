package app

import (
	"context"
	"errors"

	"github.com/ArtixSx/razvilka/internal/components"
)

// The ordinary authenticated component action supplies the user's request.
// Root/retained controller admission and the original control epoch remain
// actual owners; no installed-package DTO authorizes the opkg transaction.
func (a *App) installInitialNFQWS(ctx context.Context) (components.Result, error) {
	if a == nil || a.Components == nil || a.Dataplane == nil || a.Store == nil || a.ComponentHistory == nil {
		return components.Result{}, components.NoMutation(components.ErrNFQWSInitialInstall)
	}
	held, release, err := a.privateExclusiveOperation(ctx)
	if err != nil {
		return components.Result{}, components.NoMutation(err)
	}
	defer release()
	guard, err := a.componentUpdateGuard(held)
	if err != nil {
		return components.Result{}, components.NoMutation(err)
	}
	control, err := a.managedNFQControl(held)
	defer a.closeUnretainedManagedNFQControl(control)
	if err != nil {
		return components.Result{}, components.NoMutation(err)
	}
	cfg, ref := a.Store.Get(), control.Reference()
	authority := components.NFQWSInitialInstallAuthority{InstallationID: ref.InstallationID, Sequence: ref.Sequence, Revision: cfg.Revision,
		Check: func(c context.Context, installation string, sequence, revision uint64, reader int) error {
			if installation != ref.InstallationID || sequence != ref.Sequence || revision != cfg.Revision || reader != components.NFQWSInitialInstallSchema {
				return components.ErrRecoveryAuthority
			}
			if err := a.Operations.WithExclusiveContext(c, func() error { return nil }); err != nil {
				return err
			}
			return errors.Join(guard(c), control.Current(c), a.managedNFQConfigCurrent(c, cfg), a.managedNFQHistoryCurrent(c))
		},
	}
	return a.Components.InstallInitialNFQWS(held, authority)
}
