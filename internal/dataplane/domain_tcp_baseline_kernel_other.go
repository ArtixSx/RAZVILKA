//go:build !linux

package dataplane

import "context"

func domainTCPBaselineForwarding(context.Context, *networkPolicyIdentity) error {
	return ErrDomainTCPBaselineKernel
}
