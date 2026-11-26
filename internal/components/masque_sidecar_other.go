//go:build !linux

package components

import "context"

func (m *Manager) InstallInitialMASQUESidecar(context.Context, func(context.Context) error, func(context.Context, func() error) error) (Result, error) {
	return Result{Component: MASQUESidecarComponent, Action: "install"}, NoMutation(ErrMASQUESidecarUnsupported)
}

func CheckInitialMASQUESidecarPublication(context.Context) error {
	return ErrMASQUESidecarUnsupported
}
