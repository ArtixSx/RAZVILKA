package dataplane

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync/atomic"
)

// Used at mutation boundaries after potentially slow resolution/health probes.
// Manager wraps the caller guard with its fresh WAN check for committed refreshes.
func checkAddressRefreshAuthority(ctx context.Context) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if guard, ok := ctx.Value(reviewGuardKey{}).(func(context.Context) error); ok && guard != nil {
		return guard(ctx)
	}
	return nil
}

// An incomplete refresh must not silently remove the old rules for the failed
// half of a service. Initial discovery has different semantics; this stricter
// wrapper applies only to refreshing an already committed policy. Per-domain
// TTL/grace retention is future work, not an unbounded union of stale addresses.
func resolveRefreshPolicyRules(ctx context.Context, plan Plan, id string, resolver PrefixResolver) ([]string, []PolicyRule, error) {
	if resolver == nil {
		resolver = func(c context.Context, h string) ([]netip.Addr, error) {
			return net.DefaultResolver.LookupNetIP(c, "ip", h)
		}
	}
	var incomplete atomic.Bool
	checked := func(c context.Context, h string) ([]netip.Addr, error) {
		addresses, err := resolver(c, h)
		bad := err != nil || len(addresses) == 0
		for _, ip := range addresses {
			ip = ip.Unmap()
			bad = bad || !ip.IsValid() || !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast()
		}
		if bad {
			incomplete.Store(true)
		}
		return addresses, err
	}
	prefixes, rules, err := resolvePolicyRules(ctx, plan, id, checked)
	if ctx.Err() != nil {
		return nil, nil, ctx.Err()
	}
	if incomplete.Load() {
		return nil, nil, ErrDNSRefreshIncomplete
	}
	return prefixes, rules, err
}

var ErrDNSRefreshIncomplete = errors.New("address-refresh-dns-incomplete")
