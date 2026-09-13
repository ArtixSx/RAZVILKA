package dataplane

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"time"

	"github.com/ArtixSx/razvilka/internal/publicfetch"
)

// Pin a publicly routable endpoint into the staged runtime so awg/awg-quick
// cannot resolve the same hostname a second time to a different, private IP.
// The original hostname remains in the user's profile for future refresh.
func (a *WARPWireGuardAdapter) pinAWGEndpoint(ctx context.Context, content string) (string, error) {
	endpoint, err := wgEndpoint(content)
	if err != nil {
		return "", err
	}
	host, port, err := net.SplitHostPort(endpoint)
	if err != nil {
		return "", errors.New("invalid AWG endpoint")
	}
	addresses := []netip.Addr{}
	if ip, err := netip.ParseAddr(host); err == nil {
		addresses = append(addresses, ip)
	} else {
		resolver := a.Resolver
		if resolver == nil {
			resolver = func(ctx context.Context, host string) ([]netip.Addr, error) {
				return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
			}
		}
		ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		addresses, err = resolver(ctx, host)
		if err != nil || len(addresses) == 0 || len(addresses) > 32 {
			return "", errors.New("AWG endpoint resolution unavailable or exceeds limit")
		}
	}
	for _, ip := range addresses {
		if !publicfetch.PublicAddress(ip) {
			return "", errors.New("AWG endpoint resolved to a non-public address")
		}
	}
	if len(addresses) == 0 {
		return "", errors.New("AWG endpoint has no address")
	}
	chosen := addresses[0].Unmap()
	for _, ip := range addresses {
		if ip.Unmap().Is4() {
			chosen = ip.Unmap()
			break
		}
	}
	pinned, err := replaceWGEndpoint([]byte(content), net.JoinHostPort(chosen.String(), port))
	return string(pinned), err
}
