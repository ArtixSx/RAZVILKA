//go:build !linux

package dataplane

import "context"

func (*XrayDomainTCPExecutionResource) observeDomainListener(context.Context) (xraySelectedTCPListenerObservation, error) {
	return xraySelectedTCPListenerObservation{}, ErrXrayDomainTCPOriginal
}

func (*XrayDomainTCPExecutionResource) observeDomainListenerAbsent(context.Context) error {
	return ErrXrayDomainTCPOriginal
}
