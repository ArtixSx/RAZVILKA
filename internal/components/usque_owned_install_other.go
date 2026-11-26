//go:build !linux

package components

import "context"

func (m *Manager) InstallInitialUSQUE(context.Context, func(context.Context) error) (Result, error) {
	return Result{Component: "usque", Action: "install"}, NoMutation(ErrUSQUEInstallUnsupported)
}

func (m *Manager) CheckInitialUSQUEPublication(context.Context) error {
	return ErrUSQUEInstallUnsupported
}
