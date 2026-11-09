//go:build !linux

package updatecheck

import "context"

func originalBootstrapInstallerControllerAdapter(context.Context, string) (*SelfUpdateFileAdapter, error) {
	return nil, ErrInstallerControllerRole
}
