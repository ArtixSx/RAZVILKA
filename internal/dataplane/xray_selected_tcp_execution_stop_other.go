//go:build !linux

package dataplane

import "context"

func (*XraySelectedTCPExecutionResource) stopOriginalNative(context.Context) error {
	return errXraySelectedTCPRuntime
}
