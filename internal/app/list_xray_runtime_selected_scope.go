package app

import (
	"github.com/ArtixSx/razvilka/internal/dataplane"
	"net/netip"
	"strings"
)

// Narrow only from the actual original selected-device physical observation.
// The dedicated consumer never turns a service's /32 into the bridge subnet.
func (r *XrayListRuntimeSource) narrowSelectedTCP(c *DefaultRouteCompilation) error {
	if c == nil || c.lan == nil || len(c.lan.Ingress) != 1 {
		return ErrDefaultRouteCapability
	}
	g := c.lan.Ingress[0]
	if g.Membership != "mac" || len(g.IncludedMACs) != 1 {
		return ErrDefaultRouteCapability
	}
	var client netip.Addr
	found := false
	for _, device := range r.scopeOwner().devices() {
		if device.Interface != g.Interface || !strings.EqualFold(device.MAC, g.IncludedMACs[0]) {
			continue
		}
		if found {
			return ErrListScopeChanged
		}
		found = true
		for _, raw := range device.Addresses {
			ip, err := netip.ParseAddr(raw)
			if err != nil {
				return ErrListScopeChanged
			}
			if !ip.Is4() {
				continue
			}
			if client.IsValid() {
				return ErrListScopeChanged
			}
			client = ip
		}
	}
	if !found || !client.IsValid() {
		return ErrListScopeChanged
	}
	for _, raw := range g.ExcludedSources {
		p, err := netip.ParsePrefix(raw)
		if err != nil || p.Contains(client) {
			return ErrDefaultRouteCapability
		}
	}
	var rules []DefaultRouteRule
	for _, rule := range c.rules {
		if rule.ServiceID != r.service || rule.Route != r.selected || rule.Ingress != g.Interface || !rule.Destination.Addr().Is4() {
			return ErrDefaultRouteCapability
		}
		if !rule.Source.Contains(client) {
			continue
		}
		rule.Source, rule.Protocol, rule.FirstPort, rule.LastPort = netip.PrefixFrom(client, 32), "tcp", 443, 443
		rules = append(rules, rule)
	}
	if len(rules) == 0 {
		return ErrDefaultRouteCapability
	}
	c.rules = rules
	c.lan = dataplane.CloneLANPolicyRuntime(c.lan)
	c.lan.Ingress[0].Sources = []string{netip.PrefixFrom(client, 32).String()}
	c.lan.Ingress[0].ExcludedSources = nil // Disjoint negatives cannot select this sole source.
	return nil
}
