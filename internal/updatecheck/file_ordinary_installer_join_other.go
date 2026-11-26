//go:build !linux

package updatecheck

import "context"

func (a *SelfUpdateFileAdapter) withOriginalOrdinaryInstallerJoin(context.Context, string, func(context.Context) error) error {
	return ErrOrdinaryInstallerControllerRole
}
