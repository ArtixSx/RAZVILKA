package dataplane

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"slices"
	"time"

	"github.com/ArtixSx/razvilka/internal/nodequality"
)

// A transport choice is not service proof. Stage pins the selected address in
// both config and manifest; the existing exact canary must still confirm it.
func (a *ProxyTunnelAdapter) selectScopedNodeEndpoint(parent context.Context, host string, port int) (netip.Addr, error) {
	if a == nil || parent == nil || port < 1 || port > 65535 {
		return netip.Addr{}, ErrNodeEndpointChanged
	}
	ctx, cancel := context.WithTimeout(parent, a.timeout())
	defer cancel()
	admit := func(address netip.Addr) error {
		return errors.Join(ctx.Err(), checkAddressRefreshAuthority(ctx), checkNodeResource(ctx, host, address))
	}
	if err := admit(netip.Addr{}); err != nil {
		return netip.Addr{}, err
	}
	addresses, err := a.resolveNodeEndpoint(ctx, host)
	if err != nil {
		return netip.Addr{}, errors.Join(err, ctx.Err())
	}
	addresses = slices.Clone(addresses)
	if !publicNodeAddresses(addresses) {
		return netip.Addr{}, ErrNodeEndpointChanged
	}
	// Admit the entire fresh DNS set before contacting its first address.
	for _, address := range addresses {
		if address.Zone() != "" {
			return netip.Addr{}, ErrNodeEndpointChanged
		}
		if err := admit(address.Unmap()); err != nil {
			return netip.Addr{}, err
		}
	}
	// Literal servers have no DNS choice. Preserve their existing pinning;
	// this DNS-selection fix does not add a new probe to the literal path.
	if literal, err := netip.ParseAddr(host); err == nil {
		return literal.Unmap(), admit(literal.Unmap())
	}
	dial := a.nodeEndpointDial
	if dial == nil {
		dial = func(c context.Context, endpoint netip.AddrPort) error {
			connection, err := (&net.Dialer{Timeout: 3 * time.Second}).DialContext(c, "tcp", endpoint.String())
			if err == nil {
				_ = connection.Close()
			}
			return err
		}
	}
	var refused error
	selected, err := nodequality.SelectEndpoint(ctx, addresses, true, func(c context.Context, address netip.Addr) (bool, error) {
		if refused != nil {
			return false, refused
		}
		if refused = admit(address); refused != nil {
			return false, refused
		}
		dialErr := dial(c, netip.AddrPortFrom(address, uint16(port)))
		if refused = admit(address); refused != nil {
			return false, refused
		}
		return dialErr == nil, dialErr
	}, time.Now)
	if refused != nil {
		return netip.Addr{}, refused
	}
	if err != nil {
		return netip.Addr{}, errors.Join(ErrNodeEndpointChanged, err)
	}
	return selected.Address, admit(selected.Address)
}
