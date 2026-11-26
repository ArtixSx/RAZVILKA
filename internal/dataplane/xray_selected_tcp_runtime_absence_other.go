//go:build !linux

package dataplane

import (
	"context"
	"github.com/ArtixSx/razvilka/internal/netidentity"
	"net/netip"
)

func xraySelectedTCPObserveListenerAbsent(context.Context, *netidentity.Provider, netidentity.Identity, netip.AddrPort) error {
	return errXraySelectedTCPRuntime
}
