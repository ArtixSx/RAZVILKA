package app

import (
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"reflect"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/ArtixSx/razvilka/internal/autonomy"
	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/netidentity"
	"github.com/ArtixSx/razvilka/internal/physicalscope"
)

func defaultRoutePacketFactsClone(f physicalscope.IPv4LANPacketFacts) physicalscope.IPv4LANPacketFacts {
	raw, _ := json.Marshal(f)
	var out physicalscope.IPv4LANPacketFacts
	_ = json.Unmarshal(raw, &out)
	return out
}

func nfqwsPacketMAC(raw string) (string, error) {
	m, err := net.ParseMAC(raw)
	if err != nil || len(m) != 6 || m[0]&1 != 0 || m.String() == "00:00:00:00:00:00" || m.String() != raw {
		return "", ErrDefaultRouteCapability
	}
	return m.String(), nil
}

func validateNFQWSPacketSnapshot(cfg config.Config, s NFQWSPacketScopeSnapshot) error {
	i, err := nfqwsPacketIntent(cfg)
	if err != nil {
		return err
	}
	f := s.Facts
	if !reflect.DeepEqual(i, f.Intent) || !defaultRouteScopeReferenceValid(cfg, s.Authority) || s.Authority.ApprovalRevision != i.Revision || s.Authority.PolicyRevision != i.PolicyRevision || f.Control.InstallationID != s.Authority.InstallationID || f.Control.Sequence != s.Authority.Sequence || s.DNSMode != "baseline" || !defaultRouteHash(s.NetworkID) || len(f.ScopeID) != 32 || strings.Trim(f.ScopeID, "0123456789abcdef") != "" || f.Identity.Validate() != nil || f.Identity.Kind != netidentity.ReviewedSingleInitNet {
		return dataplane.ErrReviewChanged
	}
	h := f.Home
	if !h.Home || h.Guest || h.IfIndex <= 0 || !defaultRouteInterface(h.Interface) || len(i.SegmentIDs) != 1 || (i.SegmentIDs[0] != h.ID && i.SegmentIDs[0] != h.NativeName) || len(f.IPv4Prefixes) != 1 || len(f.OwnedMACs) == 0 || len(f.OwnedMACs) > 128 || len(f.OwnedAddresses) > 512 || len(f.ExcludedMACs) > 128 {
		return ErrDefaultRouteCapability
	}
	var home4 []string
	for _, raw := range h.Prefixes {
		p, e := netip.ParsePrefix(raw)
		if e != nil || p.String() != raw || !defaultRoutePrefix(p, false) {
			return ErrDefaultRouteCapability
		}
		if p.Addr().Is4() {
			home4 = append(home4, raw)
		}
	}
	if !slices.Equal(home4, f.IPv4Prefixes) {
		return ErrDefaultRouteCapability
	}
	expected := []string{}
	for _, id := range i.ExcludedDeviceIDs {
		raw := strings.ReplaceAll(strings.TrimPrefix(id, "mac-"), "-", ":")
		mac, e := nfqwsPacketMAC(raw)
		if e != nil || id != "mac-"+strings.ReplaceAll(mac, ":", "-") {
			return ErrDefaultRouteCapability
		}
		expected = append(expected, mac)
	}
	slices.Sort(expected)
	if !slices.Equal(expected, f.ExcludedMACs) {
		return ErrDefaultRouteCapability
	}
	for _, values := range [][]string{f.OwnedMACs, f.ExcludedMACs} {
		seen := map[string]bool{}
		for _, m := range values {
			if _, e := nfqwsPacketMAC(m); e != nil || seen[m] {
				return ErrDefaultRouteCapability
			}
			seen[m] = true
		}
	}
	for _, raw := range f.OwnedAddresses {
		a, e := netip.ParseAddr(raw)
		if e != nil || a.String() != raw || a.Is4In6() || a.Zone() != "" {
			return ErrDefaultRouteCapability
		}
	}
	return nil
}

// CompileNFQWSIPv4LANPacketPolicy is deliberately separate from the general
// compiler. These detached comparisons grant no authority. Actual execution
// retains ScopeReview, the original packet scope, selected source and material.
// First slice: one Home prefix, lan_except/inherit, one TCP4 NFQ service with
// literal destinations and no per-service Sources. Unsupported cases refuse.
func CompileNFQWSIPv4LANPacketPolicy(cfg config.Config, s NFQWSPacketScopeSnapshot, services []dataplane.Route, paths map[string]DefaultRoutePath, now time.Time) (*DefaultRouteCompilation, error) {
	refuse := func(reason string) (*DefaultRouteCompilation, error) {
		return nil, fmt.Errorf("%w: NFQ IPv4 LAN packet purpose: %s", ErrDefaultRouteCapability, reason)
	}
	if now.IsZero() || cfg.Revision == 0 || cfg.Revision == ^uint64(0) {
		return nil, dataplane.ErrReviewChanged
	}
	if err := validateNFQWSPacketSnapshot(cfg, s); err != nil {
		return nil, err
	}
	if len(services) != 1 || len(paths) != 1 {
		return refuse("one exact service required")
	}
	p := config.CloneNetworkPolicy(cfg.NetworkPolicy)
	exclusions, err := config.EffectiveResourceExclusions(p)
	if err != nil {
		return refuse("resource exclusions unavailable")
	}
	// Keep every full-compiler exclusion fence. IP-wide direct exclusions may
	// be subtracted; domain/service/device-specific rules need a future bridge.
	for _, list := range [][]config.ResourceMatch{exclusions.Manual, exclusions.Russian} {
		for _, m := range list {
			if m.Kind != "ip" && m.Kind != "cidr" {
				return refuse("non-IP exclusion needs flow dispatch")
			}
		}
	}
	if len(exclusions.BroadTLDs) != 0 {
		return refuse("domain exclusions need flow dispatch")
	}
	for _, r := range p.Rules {
		if (r.Kind != "ip" && r.Kind != "cidr") || r.Action != "direct" || len(r.DeviceIDs) != 0 {
			return refuse("rule needs flow dispatch")
		}
	}
	service := defaultRouteCloneRoutes(services)[0]
	state, exists := cfg.Services[service.ServiceID]
	active := 0
	for _, v := range cfg.Services {
		if v.Enabled {
			active++
		}
	}
	path, hasPath := paths[service.ServiceID]
	if active != 1 || !exists || !state.Enabled || state.Route != "nfqws2" || service.ServiceID == "" || service.ServiceID == "default" || service.Selected != "nfqws2" || service.Resolved != "nfqws2" || len(state.Sources) != 0 || len(service.Sources) != 0 || len(service.SourceRefs) != 0 || len(service.Domains) != 0 || len(service.CIDRs) == 0 || len(service.CIDRs) > 128 || !hasPath || !defaultRoutePathValid(path) || path.NFQWS == nil || path.NFQWS.ServiceID != service.ServiceID || path.NFQWS.Protocol != "tcp" || path.NFQWS.IPFamily != "ipv4" || len(path.NFQWS.Traffic) == 0 {
		return refuse("only the exact literal TCP4 NFQ source is supported")
	}
	destinations, err := defaultRouteParsePrefixes(service.CIDRs, true)
	if err != nil {
		return nil, err
	}
	for _, d := range destinations {
		if !d.Addr().Is4() {
			return refuse("IPv6 or mixed destinations unsupported")
		}
	}
	f := s.Facts
	source := netip.MustParsePrefix(f.IPv4Prefixes[0])
	gate := DefaultRouteIngress{SegmentID: f.Intent.SegmentIDs[0], Interface: f.Home.Interface, Sources: []netip.Prefix{source}}
	gate.ExcludedMACs = append(slices.Clone(f.OwnedMACs), f.ExcludedMACs...)
	for _, r := range f.Home.RouterNeighbors {
		m, e := nfqwsPacketMAC(r.MAC)
		if e != nil {
			return nil, e
		}
		gate.ExcludedMACs = append(gate.ExcludedMACs, m)
	}
	slices.Sort(gate.ExcludedMACs)
	gate.ExcludedMACs = slices.Compact(gate.ExcludedMACs)
	negative, err := defaultRouteParsePrefixes(p.Clients.ExcludedCIDRs, false)
	if err != nil {
		return nil, err
	}
	for _, raw := range f.OwnedAddresses {
		a, _ := netip.ParseAddr(raw)
		if a.Is4() {
			negative = append(negative, netip.PrefixFrom(a, 32))
		}
	}
	gate.ExcludedSources = defaultRouteIntersections(gate.Sources, negative)
	available, err := defaultRouteSubtractPrefixes(gate.Sources, gate.ExcludedSources)
	if err != nil {
		return nil, err
	}
	if len(available) == 0 {
		return refuse("empty source scope")
	}
	public, err := defaultRoutePublic(p)
	if err != nil {
		return nil, err
	}
	destinations = defaultRouteIntersections(public, destinations)
	if len(destinations) == 0 {
		return refuse("empty destination scope")
	}
	// Keep only comparison scope identity. No manufactured membership, provider
	// proof, observed addresses or DeviceBindings enter the full compiler.
	snapshot := DefaultRouteSnapshot{Scope: autonomy.ScopeObservation{BootID: f.Identity.BootID, NetworkID: s.NetworkID, Revision: f.Intent.Revision}, Authority: s.Authority, DNSMode: s.DNSMode, Paths: paths}
	snapshot = defaultRouteClone(snapshot)
	c := &DefaultRouteCompilation{policy: p, snapshot: snapshot, ingress: []DefaultRouteIngress{gate}, packet: &s, packetServices: defaultRouteCloneRoutes(services)}
	for _, dest := range destinations {
		for _, traffic := range path.NFQWS.Traffic {
			if traffic.Protocol != "tcp" || traffic.IPFamily != "ipv4" || traffic.First == 0 || traffic.Last < traffic.First {
				return refuse("UDP/mixed traffic unsupported")
			}
			c.rules = append(c.rules, DefaultRouteRule{ServiceID: service.ServiceID, Origin: "override", Route: "nfqws2", Ingress: gate.Interface, Source: source, Destination: dest, Protocol: "tcp", FirstPort: traffic.First, LastPort: traffic.Last})
			if len(c.rules) > defaultRouteRuleLimit {
				return nil, defaultRouteBound()
			}
		}
	}
	sort.Slice(c.rules, func(i, j int) bool { return defaultRouteRuleKey(c.rules[i]) < defaultRouteRuleKey(c.rules[j]) })
	// ScopeID is an opaque live lifetime nonce. Review compares stable facts;
	// execution still requires the original live scope and bound immutable plan.
	stable := s
	stable.Facts.ScopeID = ""
	c.digest = defaultRouteDigest(struct {
		Revision uint64
		Policy   *config.NetworkPolicy
		Scope    NFQWSPacketScopeSnapshot
		Paths    map[string]DefaultRoutePath
		Services []dataplane.Route
		Rules    []DefaultRouteRule
		Ingress  []DefaultRouteIngress
	}{cfg.Revision, p, stable, snapshot.Paths, c.packetServices, c.rules, c.ingress})
	lan, err := defaultRouteCompileLAN(c.digest, c.ingress)
	if err != nil {
		return nil, err
	}
	c.lan, err = dataplane.CompileNFQWSDirectLANPolicyRuntime(c.digest, lan.Ingress)
	if err != nil {
		return nil, err
	}
	// Detach all packet slices as well as source comparisons from the caller.
	c.packet = &NFQWSPacketScopeSnapshot{Facts: defaultRoutePacketFactsClone(s.Facts), Authority: s.Authority, NetworkID: s.NetworkID, DNSMode: s.DNSMode}
	return c, nil
}
