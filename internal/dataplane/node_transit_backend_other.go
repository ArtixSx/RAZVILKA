//go:build !linux

package dataplane

import (
	"context"
	"net/netip"
)

func nodeRouterReturnPath(context.Context, string) error { return ErrNodeTransitUnavailable }
func (a *ProxyTunnelAdapter) nodeRouterBackendDisjoint(context.Context, proxyNodeManifest, netip.Addr, netip.Addr) error {
	return ErrNodeTransitUnavailable
}
