package dataplane

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"net/url"
	"sort"
)

const maxNodeServiceIPv4 = 4

// Resolve locally just as policy compilation does. Never choose one lucky
// address from a larger set: every admitted IPv4 must pass the literal path.
func resolveNodeServiceIPv4(ctx context.Context, rawURL string, resolver PrefixResolver) ([]netip.Addr, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	target, err := url.Parse(rawURL)
	if err != nil || target.Scheme != "https" || target.Hostname() == "" || target.User != nil || target.Fragment != "" || target.Port() != "" && target.Port() != "443" {
		return nil, errors.New("node service IP probe requires its original HTTPS target")
	}
	if resolver == nil {
		resolver = func(ctx context.Context, host string) ([]netip.Addr, error) {
			return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		}
	}
	addresses, err := resolver(ctx, target.Hostname())
	if err != nil || !publicNodeAddresses(addresses) {
		return nil, errors.New("node service DNS did not return an entirely public bounded set")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	unique := map[netip.Addr]bool{}
	for _, address := range addresses {
		address = address.Unmap()
		if address.Is4() {
			unique[address] = true
		}
	}
	if len(unique) == 0 || len(unique) > maxNodeServiceIPv4 {
		return nil, errors.New("node service IPv4 proof is unavailable or exceeds its bound")
	}
	result := make([]netip.Addr, 0, len(unique))
	for address := range unique {
		result = append(result, address)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Less(result[j]) })
	return result, nil
}

func probeTunnelViaSOCKSIP(ctx context.Context, rawURL, address string, pinned netip.Addr) error {
	response, cleanup, err := socksHTTPGetPinned(ctx, rawURL, address, pinned)
	if cleanup != nil {
		defer cleanup()
	}
	if err != nil {
		return err
	}
	defer response.Body.Close()
	_, err = strictServiceResponse(rawURL, response)
	return err
}

func (a *ProxyTunnelAdapter) probeNodeServiceIP(ctx context.Context, rawURL, address string) error {
	addresses, err := resolveNodeServiceIPv4(ctx, rawURL, a.Resolver)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return errors.New("node service IP path unavailable: public IPv4 DNS proof required")
	}
	probe := a.ServiceIPProbe
	if probe == nil {
		probe = probeTunnelViaSOCKSIP
	}
	for _, pinned := range addresses {
		probeCtx, cancel := context.WithTimeout(ctx, a.timeout())
		err := probe(probeCtx, rawURL, address, pinned)
		cancel()
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return errors.New("node service IP path unsupported or unavailable; repeat an exact IP-path check")
		}
	}
	return ctx.Err()
}
