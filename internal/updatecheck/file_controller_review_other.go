//go:build !linux

package updatecheck

import "context"

func (a *SelfUpdateFileAdapter) ordinaryInstallerControllerReview(context.Context, string) (bool, error) {
	return false, ErrOrdinaryInstallerControllerRole
}
