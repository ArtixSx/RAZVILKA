//go:build !linux

package dataplane

import "context"

func (*XrayDomainTCPExecutionResource) startOriginalNative(context.Context) error {
	return ErrXrayDomainTCPOriginal
}
func (*XrayDomainTCPExecutionResource) stopOriginalNative(context.Context) error {
	return ErrXrayDomainTCPOriginal
}
