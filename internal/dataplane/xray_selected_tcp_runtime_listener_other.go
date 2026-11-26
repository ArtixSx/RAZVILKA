//go:build !linux

package dataplane

import (
	"context"
	"net/netip"

	"github.com/ArtixSx/razvilka/internal/netidentity"
)

func (*xraySelectedTCPProcess) observeListener(context.Context, *netidentity.Provider, netidentity.Identity, netip.AddrPort) (xraySelectedTCPListenerObservation, error) {
	return xraySelectedTCPListenerObservation{}, errXraySelectedTCPRuntime
}
