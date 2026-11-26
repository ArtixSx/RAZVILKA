//go:build !linux

package dataplane

import "context"

func (*XraySelectedTCPExecutionResource) startOriginalNative(context.Context) error {
	return errXraySelectedTCPRuntime
}
