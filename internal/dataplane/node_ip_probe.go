package dataplane

import (
	"context"
	"errors"
	"net/netip"
	"net/url"
	"sort"
	"strings"

	"github.com/ArtixSx/razvilka/internal/netresolve"
	"github.com/ArtixSx/razvilka/internal/routekind"
)

// Common CDN-backed services return five or more IPv4 addresses. Keep the
// complete admitted set bounded without rejecting those ordinary answers.
// Every address must still pass, within the checker's overall time budget.
const maxNodeServiceIPv4 = 8

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
			return netresolve.LookupNetIP(ctx, "ip", host)
		}
	}
	if err := checkNodeResource(ctx, target.Hostname(), netip.Addr{}); err != nil {
		return nil, err
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
		if err := checkNodeResource(ctx, target.Hostname(), address); err != nil {
			return nil, err
		}
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

func (a *ProxyTunnelAdapter) nodeServiceIPScopeRequired(route Route) bool {
	if route.NetworkPolicyGeneration != "" || route.NetworkPolicyRole != "" || a.scopedXray && len(route.Domains) == 0 {
		return true
	}
	// Exact node runtimes materialize CIDR-only routes with a rejecting
	// default. An opaque SOCKS hostname is outside that finite ruleset.
	// Use the existing admitted literal path with the original TLS identity;
	// generic profiles, unresolved groups and other adapters gain no scope.
	engine, target, exact := routekind.ParseNodeRoute(route.Resolved)
	return exact && engine == a.ID() && (engine == "sing-box" || engine == "xray") && strings.HasPrefix(target, "node-") && len(route.Domains) == 0 && len(route.CIDRs) != 0
}

// Admit the complete set before starting a candidate or probing its first pin.
// The reviewed CIDRs already contain resource negatives; DNS cannot add a new
// destination to them. Legacy domain diagnostics retain their existing scope.
func (a *ProxyTunnelAdapter) admittedNodeServiceIPv4(ctx context.Context, route Route) ([]netip.Addr, error) {
	if err := checkAddressRefreshAuthority(ctx); err != nil {
		return nil, err
	}
	finite := a.nodeServiceIPScopeRequired(route)
	if finite && (len(route.Domains) != 0 || len(route.CIDRs) == 0) {
		return nil, ErrNodeResourceDenied
	}
	addresses, err := resolveNodeServiceIPv4(ctx, route.ProbeURL, a.Resolver)
	if err != nil {
		return nil, err
	}
	origin, _ := url.Parse(route.ProbeURL)
	literal, literalErr := netip.ParseAddr(origin.Hostname())
	for _, pinned := range addresses {
		if literalErr == nil && literal != pinned || finite && !nodeRouterPinInScope(pinned, route.CIDRs) {
			return nil, ErrNodeResourceDenied
		}
	}
	if err := checkAddressRefreshAuthority(ctx); err != nil {
		return nil, err
	}
	return addresses, nil
}

func (a *ProxyTunnelAdapter) probeNodeServiceIP(ctx context.Context, route Route, address string) error {
	addresses, err := a.admittedNodeServiceIPv4(ctx, route)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if errors.Is(err, ErrNodeResourceDenied) || errors.Is(err, ErrReviewChanged) {
			return err
		}
		return errors.New("node service IP path unavailable: public IPv4 DNS proof required")
	}
	return a.probeNodeServiceIPPins(ctx, route, address, addresses)
}

func (a *ProxyTunnelAdapter) probeNodeServiceIPPins(ctx context.Context, route Route, address string, addresses []netip.Addr) error {
	probe := a.ServiceIPProbe
	if probe == nil {
		probe = probeTunnelViaSOCKSIP
	}
	for _, pinned := range addresses {
		if err := checkAddressRefreshAuthority(ctx); err != nil {
			return err
		}
		if err := checkNodeResourceURL(ctx, route.ProbeURL, pinned); err != nil {
			return err
		}
		probeCtx, cancel := context.WithTimeout(ctx, a.timeout())
		err := probe(probeCtx, route.ProbeURL, address, pinned)
		cancel()
		if guardErr := errors.Join(checkAddressRefreshAuthority(ctx), checkNodeResourceURL(ctx, route.ProbeURL, pinned)); guardErr != nil {
			return guardErr
		}
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			// Preserve only the bounded semantic result from our HTTPS evaluator.
			// Transport diagnostics can contain endpoints and are not attribution.
			var response *serviceResponseError
			if errors.As(err, &response) {
				return response
			}
			return errors.New("node service IP path unsupported or unavailable; repeat an exact IP-path check")
		}
	}
	return ctx.Err()
}
