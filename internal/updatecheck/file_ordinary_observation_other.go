//go:build !linux

package updatecheck

import "context"

func (a *SelfUpdateFileAdapter) withOrdinaryInstallerControllerObservation(context.Context, string, func(context.Context, *OrdinaryInstallerControllerObservation) error) error {
	return ErrOrdinaryInstallerControllerRole
}
