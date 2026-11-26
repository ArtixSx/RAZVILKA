package app

import (
	"context"
	"errors"

	"github.com/ArtixSx/razvilka/internal/components"
)

// The authenticated component action or the autopilot supplies the request.
// The autopilot also supplies its live consent and scope check. Both paths
// retain the original controller admission and control epoch.
func (a *App) installInitialNFQWS(ctx context.Context, authorize func(context.Context) error) (components.Result, error) {
	if a == nil || a.Components == nil || a.Dataplane == nil || a.Store == nil || a.ComponentHistory == nil {
		return components.Result{}, components.NoMutation(components.ErrNFQWSInitialInstall)
	}
	held, release, err := a.privateExclusiveOperation(ctx)
	if err != nil {
		return components.Result{}, components.NoMutation(err)
	}
	defer release()
	if authorize != nil {
		if err := authorize(held); err != nil {
			return components.Result{}, components.NoMutation(err)
		}
	}
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
			if authorize != nil {
				if err := authorize(c); err != nil {
					return err
				}
			}
			return errors.Join(guard(c), control.Current(c), a.managedNFQConfigCurrent(c, cfg), a.managedNFQHistoryCurrent(c))
		},
	}
	return a.Components.InstallInitialNFQWS(held, authority)
}
