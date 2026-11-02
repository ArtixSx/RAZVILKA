//go:build !linux || (!amd64 && !arm64)

package startuptools

import (
	"context"
	"github.com/ArtixSx/razvilka/internal/dataplane"
	"net/netip"
)

func (*syntheticDNSRunner) ReadDomainTCPBaseline(context.Context, netip.Addr, netip.Addr, string) (dataplane.DomainTCPBaselineReadImage, error) {
	return dataplane.DomainTCPBaselineReadImage{}, at("DOMAIN_BASELINE_PLATFORM", nil)
}
