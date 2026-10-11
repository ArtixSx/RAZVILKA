//go:build !linux

package updatecheck

import "context"

func (a *SelfUpdateFileAdapter) verifyOrdinaryInstallerControllerRole(context.Context, string, int) error {
	return ErrOrdinaryInstallerControllerRole
}

func originalOrdinaryInstallerControllerAdapter(context.Context, string) (*SelfUpdateFileAdapter, error) {
	return nil, ErrOrdinaryInstallerControllerRole
}
