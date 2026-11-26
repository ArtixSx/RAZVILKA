//go:build !linux

package updatecheck

import "context"

func (a *SelfUpdateFileAdapter) verifyInstallerControllerRole(context.Context, string, int) error {
	return ErrInstallerControllerRole
}
