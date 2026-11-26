//go:build !linux

package dataplane

import "context"

func (*XrayDomainTCPExecutionResource) observeDomainProcess(context.Context) (xraySelectedTCPProcessObservation, error) {
	return xraySelectedTCPProcessObservation{}, ErrXrayDomainTCPOriginal
}
