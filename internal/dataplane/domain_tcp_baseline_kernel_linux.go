//go:build linux

package dataplane

import (
	"context"
	"github.com/ArtixSx/razvilka/internal/netidentity"
	"os"
)

func domainTCPBaselineForwarding(ctx context.Context, original *networkPolicyIdentity) error {
	if original == nil || original.provider == nil || xraySelectedTCPFinite(ctx) != nil {
		return ErrDomainTCPBaselineKernel
	}
	return original.provider.WithCurrent(ctx, func(held context.Context, actual netidentity.Identity) error {
		if actual != original.value {
			return ErrDomainTCPBaselineKernel
		}
		proc, err := openXraySelectedTCPProc(held, os.Getpid())
		if err != nil {
			return err
		}
		defer proc.close()
		if err := proc.network(held, actual); err != nil {
			return err
		}
		if err := domainTCPBaselineQdiscs(held); err != nil {
			return err
		}
		if err := domainTCPBaselinePrograms(held, proc); err != nil {
			return err
		}
		data, err := proc.read(held, proc.root, "sys/net/ipv4/ip_forward", 2)
		if err != nil || string(data) != "1\n" || proc.network(held, actual) != nil || proc.current(held) != nil {
			return ErrDomainTCPBaselineKernel
		}
		return held.Err()
	})
}
