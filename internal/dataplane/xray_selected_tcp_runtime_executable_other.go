//go:build !linux

package dataplane

import "context"

func holdXraySelectedTCPExecutable(context.Context, *XrayOperationMaterial) (*xraySelectedTCPExecutable, error) {
	return nil, errXraySelectedTCPRuntime
}
func holdXraySelectedTCPExecutableLocked(context.Context, *XrayOperationMaterial) (*xraySelectedTCPExecutable, error) {
	return nil, errXraySelectedTCPRuntime
}
func (*xraySelectedTCPExecutable) current(context.Context) error { return errXraySelectedTCPRuntime }
func (*xraySelectedTCPExecutable) close() error                  { return errXraySelectedTCPRuntime }
