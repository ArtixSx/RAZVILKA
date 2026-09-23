package config

import (
	"errors"
	"net/netip"
	"slices"
	"strings"

	"golang.org/x/net/idna"
	"golang.org/x/net/publicsuffix"
)

// NetworkPolicy separates client membership from traffic selection. Nil keeps
// the existing per-service scope unchanged; it is never migrated from AllLAN.
// This is intent, not packet classification or a permission to use an adapter.
type NetworkPolicy struct {
	Schema   int               `json:"schema"`
	Revision uint64            `json:"revision"`
	Clients  ClientScope       `json:"clients"`
	Traffic  TrafficSelection  `json:"traffic"`
	Rules    []NetworkRule     `json:"rules"`
	Russian  RussianExclusions `json:"russian"`
}

type ClientScope struct {
	Mode              string   `json:"mode"` // selected_devices or lan_except
	SegmentIDs        []string `json:"segment_ids"`
	DeviceIDs         []string `json:"device_ids"`
	ExcludedDeviceIDs []string `json:"excluded_device_ids"`
	ExcludedCIDRs     []string `json:"excluded_cidrs"`
	NewDevices        string   `json:"new_devices"` // inherit or base; not new segments
}

type TrafficSelection struct {
	Mode                string `json:"mode"` // selected_services or separately allowed all_except
	DefaultRoute        string `json:"default_route,omitempty"`
	AllExceptAllowed    bool   `json:"all_except_allowed"`
	AutoHostlistAllowed bool   `json:"auto_hostlist_allowed"`
	Unavailable         string `json:"unavailable"` // retain or base
}

type NetworkRule struct {
	ID        string   `json:"id"`
	Revision  uint64   `json:"revision"`
	Kind      string   `json:"kind"` // exact, suffix, ip, cidr
	Value     string   `json:"value"`
	Action    string   `json:"action"` // direct or bypass
	Mandatory bool     `json:"mandatory"`
	DeviceIDs []string `json:"device_ids"` // empty means managed scope only
}

type RussianExclusions struct {
	Enabled           bool     `json:"enabled"`
	AutoUpdateAllowed bool     `json:"auto_update_allowed"`
	CatalogID         string   `json:"catalog_id,omitempty"`
	Revision          uint64   `json:"revision"`
	Digest            string   `json:"digest,omitempty"`
	ServiceIDs        []string `json:"service_ids"`
	BroadTLDs         []string `json:"broad_tlds"` // only explicitly chosen ru, xn--p1ai, su
}

var ErrNetworkPolicy = errors.New("invalid home network policy")

// PolicyDomain canonicalizes a name, not a URL. Public suffixes and private
// hosting suffixes cannot masquerade as a curated service definition.
func PolicyDomain(value string) (string, error) {
	if value == "" || strings.TrimSpace(value) != value || strings.ContainsAny(value, "/:@?#*\\") {
		return "", ErrNetworkPolicy
	}
	name, err := idna.Lookup.ToASCII(strings.TrimSuffix(value, "."))
	if err != nil || len(name) > 253 {
		return "", ErrNetworkPolicy
	}
	name = strings.ToLower(name)
	if _, err := netip.ParseAddr(name); err == nil {
		return "", ErrNetworkPolicy
	}
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' || strings.Trim(label, "abcdefghijklmnopqrstuvwxyz0123456789-") != "" {
			return "", ErrNetworkPolicy
		}
	}
	suffix, _ := publicsuffix.PublicSuffix(name)
	if suffix == name || !strings.Contains(name, ".") {
		return "", ErrNetworkPolicy
	}
	return name, nil
}

func policyIDs(values []string, limit int) bool {
	if len(values) > limit {
		return false
	}
	seen := map[string]bool{}
	for _, id := range values {
		if !policyIdentifier.MatchString(id) || seen[id] {
			return false
		}
		seen[id] = true
	}
	return true
}

func policyPrefix(value string) (netip.Prefix, bool) {
	p, err := netip.ParsePrefix(value)
	if err != nil || p != p.Masked() || p.Addr().Is4In6() || p.Addr().Zone() != "" || p.Addr().IsUnspecified() || p.Addr().IsMulticast() || p.Addr().IsLoopback() || p.Addr().IsLinkLocalUnicast() {
		return p, false
	}
	minimum := 8
	if p.Addr().Is6() {
		minimum = 16
	}
	return p, p.Bits() >= minimum
}

func ValidateNetworkPolicy(p *NetworkPolicy) error {
	if p == nil {
		return nil
	}
	if p.Schema != 1 || p.Revision == 0 || p.Revision == ^uint64(0) {
		return ErrNetworkPolicy
	}
	s := p.Clients
	if !slices.Contains([]string{"selected_devices", "lan_except"}, s.Mode) || !slices.Contains([]string{"inherit", "base"}, s.NewDevices) || len(s.SegmentIDs) == 0 || !policyIDs(s.SegmentIDs, 16) || !policyIDs(s.DeviceIDs, 128) || !policyIDs(s.ExcludedDeviceIDs, 128) || len(s.ExcludedCIDRs) > 64 {
		return ErrNetworkPolicy
	}
	if s.Mode == "selected_devices" && (len(s.DeviceIDs) == 0 || s.NewDevices != "base") || s.Mode == "lan_except" && len(s.DeviceIDs) != 0 {
		return ErrNetworkPolicy
	}
	seenCIDR := map[string]bool{}
	for _, value := range s.ExcludedCIDRs {
		if _, ok := policyPrefix(value); !ok || seenCIDR[value] {
			return ErrNetworkPolicy
		}
		seenCIDR[value] = true
	}
	t := p.Traffic
	if !slices.Contains([]string{"selected_services", "all_except"}, t.Mode) || !slices.Contains([]string{"retain", "base"}, t.Unavailable) {
		return ErrNetworkPolicy
	}
	if t.Mode == "selected_services" && (t.DefaultRoute != "" || t.AllExceptAllowed) {
		return ErrNetworkPolicy
	}
	if t.Mode == "all_except" {
		if !t.AllExceptAllowed || !(t.DefaultRoute == "usque" || t.DefaultRoute == "warp-wg" || t.DefaultRoute == "xray" || strings.HasPrefix(t.DefaultRoute, "sing-box:node-") && policyIdentifier.MatchString(t.DefaultRoute[len("sing-box:"):])) {
			return ErrNetworkPolicy
		}
	}
	if len(p.Rules) > 256 {
		return ErrNetworkPolicy
	}
	seen := map[string]bool{}
	for _, rule := range p.Rules {
		if !policyIdentifier.MatchString(rule.ID) || seen[rule.ID] || rule.Revision == 0 || rule.Revision == ^uint64(0) || !policyIDs(rule.DeviceIDs, 128) || !slices.Contains([]string{"direct", "bypass"}, rule.Action) || rule.Action == "direct" && !rule.Mandatory {
			return ErrNetworkPolicy
		}
		seen[rule.ID] = true
		switch rule.Kind {
		case "exact", "suffix":
			name, err := PolicyDomain(rule.Value)
			if err != nil || name != rule.Value {
				return ErrNetworkPolicy
			}
		case "ip":
			ip, err := netip.ParseAddr(rule.Value)
			if err != nil || ip.String() != rule.Value || ip.Is4In6() || ip.Zone() != "" || ip.IsUnspecified() || ip.IsMulticast() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
				return ErrNetworkPolicy
			}
		case "cidr":
			if _, ok := policyPrefix(rule.Value); !ok {
				return ErrNetworkPolicy
			}
		default:
			return ErrNetworkPolicy
		}
	}
	for i, first := range p.Rules {
		for _, second := range p.Rules[i+1:] {
			if first.Mandatory && second.Mandatory && first.Action != second.Action && NetworkRulesOverlap(first, second) {
				return ErrNetworkPolicy
			}
		}
	}
	r := p.Russian
	if !policyIDs(r.ServiceIDs, 128) || len(r.BroadTLDs) > 3 {
		return ErrNetworkPolicy
	}
	if r.Enabled {
		if !policyIdentifier.MatchString(r.CatalogID) || r.Revision == 0 || len(r.Digest) != 64 || strings.Trim(r.Digest, "0123456789abcdef") != "" || len(r.ServiceIDs) == 0 && len(r.BroadTLDs) == 0 {
			return ErrNetworkPolicy
		}
	} else if r.AutoUpdateAllowed || len(r.BroadTLDs) != 0 {
		return ErrNetworkPolicy
	}
	seen = map[string]bool{}
	for _, tld := range r.BroadTLDs {
		if !slices.Contains([]string{"ru", "xn--p1ai", "su"}, tld) || seen[tld] {
			return ErrNetworkPolicy
		}
		seen[tld] = true
	}
	return nil
}

func NetworkRulesOverlap(a, b NetworkRule) bool {
	if len(a.DeviceIDs) > 0 && len(b.DeviceIDs) > 0 {
		shared := false
		for _, id := range a.DeviceIDs {
			if slices.Contains(b.DeviceIDs, id) {
				shared = true
				break
			}
		}
		if !shared {
			return false
		}
	}
	domain := func(r NetworkRule) bool { return r.Kind == "exact" || r.Kind == "suffix" }
	if domain(a) && domain(b) {
		matches := func(r NetworkRule, name string) bool {
			return r.Value == name || r.Kind == "suffix" && strings.HasSuffix(name, "."+r.Value)
		}
		return matches(a, b.Value) || matches(b, a.Value)
	}
	prefix := func(r NetworkRule) (netip.Prefix, bool) {
		if r.Kind == "ip" {
			ip, err := netip.ParseAddr(r.Value)
			return netip.PrefixFrom(ip, ip.BitLen()), err == nil
		}
		if r.Kind == "cidr" {
			p, err := netip.ParsePrefix(r.Value)
			return p, err == nil
		}
		return netip.Prefix{}, false
	}
	pa, oka := prefix(a)
	pb, okb := prefix(b)
	return oka && okb && pa.Overlaps(pb)
}

func CloneNetworkPolicy(p *NetworkPolicy) *NetworkPolicy {
	if p == nil {
		return nil
	}
	v := *p
	v.Clients.SegmentIDs = slices.Clone(p.Clients.SegmentIDs)
	v.Clients.DeviceIDs = slices.Clone(p.Clients.DeviceIDs)
	v.Clients.ExcludedDeviceIDs = slices.Clone(p.Clients.ExcludedDeviceIDs)
	v.Clients.ExcludedCIDRs = slices.Clone(p.Clients.ExcludedCIDRs)
	v.Rules = slices.Clone(p.Rules)
	for i := range v.Rules {
		v.Rules[i].DeviceIDs = slices.Clone(p.Rules[i].DeviceIDs)
	}
	v.Russian.ServiceIDs = slices.Clone(p.Russian.ServiceIDs)
	v.Russian.BroadTLDs = slices.Clone(p.Russian.BroadTLDs)
	return &v
}
