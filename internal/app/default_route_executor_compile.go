package app

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/ArtixSx/razvilka/internal/autonomy"
	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/dataplane"
)

const defaultRouteRuleLimit = 1024

var ErrDefaultRouteCapability = errors.New("NETWORK_POLICY_EXECUTOR_REQUIRED")

// DefaultRouteAuthority is read from the shared durable control owner. A
// snapshot is a review binding; only Admit below grants mutation authority.
type DefaultRouteAuthority struct {
	InstallationID string
	Sequence       uint64
	ConsentDigest  string
}

// DefaultRouteDevice extends the platform's MAC binding with currently
// confirmed addresses. Excluded MACs also remain negative runtime gates: a
// DNS answer or a lease snapshot cannot authorize an excluded device.
type DefaultRouteDevice struct {
	ID        string
	Addresses []netip.Addr
}

// DefaultRoutePath contains references to existing checked profiles/proofs,
// never credentials or a caller-supplied capability PASS.
type DefaultRoutePath struct {
	Selected, Resolved         string
	ProfileDigest, ProofDigest string
	WireGuardProfileRevision   string
	ProbeURL                   string
}

// DefaultRouteSnapshot is supplied by trusted application/platform readers.
// Renewing freshness without changing the observation does not change review
// identity. Missing consent, bindings or generations refuses before mutation.
type DefaultRouteSnapshot struct {
	Scope                             autonomy.ScopeObservation
	Devices                           []DefaultRouteDevice
	GuestSegmentIDs                   []string
	Paths                             map[string]DefaultRoutePath // "default" or service ID
	NodeGeneration, ProfileGeneration uint64
	Authority                         DefaultRouteAuthority
	AllowedDefaultRoutes              []string
	DNSMode                           string // first capability: explicit "baseline"
	Stopped                           bool
}

type DefaultRouteRule struct {
	ServiceID, Origin, Route, Ingress string
	Source, Destination               netip.Prefix
}

type DefaultRouteIngress struct {
	SegmentID, Interface string
	Sources              []netip.Prefix
	IncludedMACs         []string // nonempty for selected devices / known-device base mode
	ExcludedSources      []netip.Prefix
	ExcludedMACs         []string
}

// DefaultRouteCompilation is immutable outside this package. The accessor
// methods copy every mutable slice/map before handing it to a shared owner.
// Overlapping IP rules must select the same resolved path. There is no
// catch-all: only enabled, reviewed service destinations enter this plan.
type DefaultRouteCompilation struct {
	policy   *config.NetworkPolicy
	snapshot DefaultRouteSnapshot
	rules    []DefaultRouteRule
	ingress  []DefaultRouteIngress
	digest   string
	lan      *dataplane.LANPolicyRuntimePlan
}

func (c *DefaultRouteCompilation) Digest() string { return c.digest }
func (c *DefaultRouteCompilation) Policy() *config.NetworkPolicy {
	return config.CloneNetworkPolicy(c.policy)
}
func (c *DefaultRouteCompilation) Rules() []DefaultRouteRule { return slices.Clone(c.rules) }
func (c *DefaultRouteCompilation) Ingress() []DefaultRouteIngress {
	result := slices.Clone(c.ingress)
	for i := range result {
		result[i].Sources = slices.Clone(result[i].Sources)
		result[i].IncludedMACs = slices.Clone(result[i].IncludedMACs)
		result[i].ExcludedSources = slices.Clone(result[i].ExcludedSources)
		result[i].ExcludedMACs = slices.Clone(result[i].ExcludedMACs)
	}
	return result
}

// CompileDefaultRoutePolicy compiles the IP-only capability. It deliberately
// does not resolve domains: shared CDN observations are never flow identity.
// Domain exclusions/overrides require the separately admitted flow bridge.
func CompileDefaultRoutePolicy(cfg config.Config, snapshot DefaultRouteSnapshot, services []dataplane.Route, now time.Time) (*DefaultRouteCompilation, error) {
	if len(services) > 128 || len(snapshot.Devices) > 512 || len(snapshot.Paths) > 129 || len(snapshot.GuestSegmentIDs) > 16 || len(snapshot.AllowedDefaultRoutes) > 128 {
		return nil, defaultRouteBound()
	}
	p := config.CloneNetworkPolicy(cfg.NetworkPolicy)
	if p == nil || config.ValidateAppliedNetworkPolicy(p) != nil || p.Traffic.Mode != "selected_services" {
		return nil, fmt.Errorf("%w: selected-services policy required", ErrDefaultRouteCapability)
	}
	exclusions, err := config.EffectiveResourceExclusions(p)
	if err != nil {
		return nil, fmt.Errorf("%w: effective resource exclusions unavailable", ErrDefaultRouteCapability)
	}
	if cfg.SafeMode || cfg.ServiceControl.Stopped || snapshot.Stopped || cfg.Revision == 0 || cfg.Revision == ^uint64(0) || now.IsZero() {
		return nil, dataplane.ErrReviewChanged
	}
	if snapshot.Authority.InstallationID == "" || snapshot.Authority.Sequence == 0 || !defaultRouteHash(snapshot.Authority.ConsentDigest) {
		return nil, fmt.Errorf("%w: control review binding unavailable", ErrDefaultRouteCapability)
	}
	if snapshot.DNSMode != "baseline" {
		return nil, fmt.Errorf("%w: general scoped DNS resolver is not implemented", ErrDefaultRouteCapability)
	}
	for _, r := range p.Rules {
		if r.Action == "bypass" {
			return nil, fmt.Errorf("%w: standalone list rule requires an exact resolved path", ErrDefaultRouteCapability)
		}
	}
	c := &DefaultRouteCompilation{policy: p, snapshot: defaultRouteClone(snapshot)}
	services = defaultRouteCloneRoutes(services)
	sort.Slice(services, func(i, j int) bool { return services[i].ServiceID < services[j].ServiceID })
	seen := map[string]bool{}
	var active []dataplane.Route
	for _, service := range services {
		state, exists := cfg.Services[service.ServiceID]
		if !exists || !state.Enabled {
			continue
		}
		if service.ServiceID == "" || service.ServiceID == "default" || seen[service.ServiceID] {
			return nil, fmt.Errorf("%w: ambiguous active service identity", ErrDefaultRouteCapability)
		}
		seen[service.ServiceID] = true
		excluded, err := exclusions.Matches(config.ResourceTarget{ServiceID: service.ServiceID})
		if err != nil {
			return nil, fmt.Errorf("%w: resource exclusion identity unavailable", ErrDefaultRouteCapability)
		}
		if !excluded {
			active = append(active, service)
		}
	}
	for id, state := range cfg.Services {
		if state.Enabled && !seen[id] {
			return nil, fmt.Errorf("%w: enabled service definition missing", ErrDefaultRouteCapability)
		}
	}
	// An empty active list needs no profile or native LAN effects. Retiring
	// previous adapters remains the existing reviewed Manager transaction.
	if len(active) == 0 {
		c.bindDigest(cfg.Revision)
		return c, nil
	}
	if snapshot.ProfileGeneration == 0 {
		return nil, dataplane.ErrReviewChanged
	}
	for _, list := range [][]config.ResourceMatch{exclusions.Manual, exclusions.Russian} {
		for _, match := range list {
			if match.Kind == "exact" || match.Kind == "suffix" {
				return nil, fmt.Errorf("%w: domain exclusions require flow dispatch", ErrDefaultRouteCapability)
			}
			if match.Kind == "service" {
				return nil, fmt.Errorf("%w: service exclusions require flow dispatch for remaining IP positives", ErrDefaultRouteCapability)
			}
		}
	}
	if len(exclusions.BroadTLDs) != 0 {
		return nil, fmt.Errorf("%w: domain exclusions require flow dispatch", ErrDefaultRouteCapability)
	}
	for _, r := range p.Rules {
		if r.Kind == "exact" || r.Kind == "suffix" {
			return nil, fmt.Errorf("%w: domain rules require flow dispatch", ErrDefaultRouteCapability)
		}
		if r.Kind == "service" {
			return nil, fmt.Errorf("%w: service exclusions require flow dispatch for remaining IP positives", ErrDefaultRouteCapability)
		}
		if r.Action != "direct" || len(r.DeviceIDs) != 0 {
			return nil, fmt.Errorf("%w: IP capability supports scope-wide direct exclusions", ErrDefaultRouteCapability)
		}
	}
	if err := c.compileIngress(now); err != nil {
		return nil, err
	}
	public, err := defaultRoutePublic(p)
	if err != nil {
		return nil, err
	}
	// Sort active entries for stable identity, but refuse conflicts instead of
	// making service order an undocumented routing priority.
	var overrides []DefaultRouteRule
	for _, service := range active {
		state, exists := cfg.Services[service.ServiceID]
		if !exists || !state.Enabled {
			continue
		} // inactive catalogue entries never create a destination rule
		if len(service.Domains) != 0 {
			return nil, fmt.Errorf("%w: ambiguous or domain-aware service override", ErrDefaultRouteCapability)
		}
		path, ok := snapshot.Paths[service.ServiceID]
		if !ok || !defaultRoutePathValid(path) || path.Selected != selectedRoute(state) || service.Selected != path.Selected || service.Resolved != path.Resolved || !slices.Equal(service.Sources, state.Sources) {
			return nil, dataplane.ErrReviewChanged
		}
		if strings.HasPrefix(path.Resolved, "wireguard:") && (service.WireGuardProfileRevision != path.WireGuardProfileRevision ||
			strings.HasPrefix(path.Selected, "wireguard:") && state.WireGuardProfileRevision != path.WireGuardProfileRevision) {
			return nil, dataplane.ErrReviewChanged
		}
		if (strings.HasPrefix(path.Resolved, "sing-box:node-") || strings.HasPrefix(path.Resolved, "xray:node-")) && snapshot.NodeGeneration == 0 {
			return nil, dataplane.ErrReviewChanged
		}
		if len(service.CIDRs) == 0 {
			return nil, fmt.Errorf("%w: IP override has no destinations", ErrDefaultRouteCapability)
		}
		destinations, err := defaultRouteParsePrefixes(service.CIDRs, true)
		if err != nil {
			return nil, err
		}
		var sourceScope []netip.Prefix
		if len(service.Sources) > 0 {
			sourceScope, err = defaultRouteParsePrefixes(service.Sources, false)
			if err != nil {
				return nil, err
			}
		}
		for _, gate := range c.ingress {
			for _, source := range gate.Sources {
				sources := []netip.Prefix{source}
				if len(sourceScope) > 0 {
					sources = defaultRouteIntersections(sources, sourceScope)
				}
				for _, src := range sources {
					for _, dest := range defaultRouteIntersections(public, destinations) {
						if src.Addr().Is4() == dest.Addr().Is4() {
							overrides = append(overrides, DefaultRouteRule{service.ServiceID, "override", path.Resolved, gate.Interface, src, dest})
							if len(overrides) > defaultRouteRuleLimit {
								return nil, defaultRouteBound()
							}
						}
					}
				}
			}
		}
	}
	if len(overrides) > defaultRouteRuleLimit {
		return nil, defaultRouteBound()
	}
	for i, left := range overrides {
		for _, right := range overrides[i+1:] {
			if left.Route != right.Route && left.Ingress == right.Ingress && left.Source.Overlaps(right.Source) && left.Destination.Overlaps(right.Destination) {
				return nil, fmt.Errorf("%w: overlapping active entries select different paths", ErrDefaultRouteCapability)
			}
		}
	}
	c.rules = slices.Clone(overrides)
	sort.Slice(c.rules, func(i, j int) bool { return defaultRouteRuleKey(c.rules[i]) < defaultRouteRuleKey(c.rules[j]) })
	c.bindDigest(cfg.Revision)
	if len(c.rules) == 0 {
		return c, nil
	}
	c.lan, err = defaultRouteCompileLAN(c.digest, c.ingress)
	if err != nil {
		return nil, fmt.Errorf("%w: shared LAN gate: %w", ErrDefaultRouteCapability, err)
	}
	return c, nil
}

func (c *DefaultRouteCompilation) bindDigest(revision uint64) {
	// Digest binds the complete reviewed policy, scope, profiles and control
	// epoch, not just the finite set of IP tuples produced from it.
	c.digest = defaultRouteDigest(struct {
		Revision uint64
		Policy   *config.NetworkPolicy
		Snapshot DefaultRouteSnapshot
		Rules    []DefaultRouteRule
	}{revision, c.policy, defaultRouteIdentity(c.snapshot), c.rules})
}

func (c *DefaultRouteCompilation) compileIngress(now time.Time) error {
	p, o := c.policy, c.snapshot.Scope
	if o.BootID == "" || o.NetworkID == "" || o.Revision == 0 || now.Before(o.ObservedAt) || !now.Before(o.FreshUntil) || o.FreshUntil.Sub(o.ObservedAt) > 2*time.Minute || len(o.Segments) > 16 || len(o.Devices) > 512 {
		return dataplane.ErrReviewChanged
	}
	segments := map[string]autonomy.HomeSegment{}
	for _, s := range o.Segments {
		if _, duplicate := segments[s.ID]; duplicate || s.ID == "" {
			return dataplane.ErrReviewChanged
		}
		segments[s.ID] = s
	}
	bindings := map[string]autonomy.DeviceBinding{}
	macs := map[string]bool{}
	for _, d := range o.Devices {
		if _, duplicate := bindings[d.ID]; duplicate || d.ID == "" {
			return dataplane.ErrReviewChanged
		}
		bindings[d.ID] = d
		if d.Confirmed && slices.Contains(p.Clients.SegmentIDs, d.SegmentID) {
			mac, err := net.ParseMAC(d.MAC)
			if err != nil || len(mac) != 6 || mac[0]&1 != 0 || mac.String() == "00:00:00:00:00:00" {
				return dataplane.ErrReviewChanged
			}
			key := d.Interface + "\x00" + mac.String()
			if macs[key] {
				return dataplane.ErrReviewChanged
			}
			macs[key] = true
		}
	}
	addresses := map[string][]netip.Addr{}
	for _, d := range c.snapshot.Devices {
		if _, duplicate := addresses[d.ID]; duplicate || len(d.Addresses) > 32 {
			return dataplane.ErrReviewChanged
		}
		binding, ok := bindings[d.ID]
		if !ok || !binding.Confirmed {
			return dataplane.ErrReviewChanged
		}
		for _, ip := range d.Addresses {
			if !ip.IsValid() || ip.Is4In6() || ip.Zone() != "" || !ip.IsGlobalUnicast() {
				return dataplane.ErrReviewChanged
			}
		}
		addresses[d.ID] = d.Addresses
	}
	for _, id := range p.Clients.SegmentIDs {
		s, ok := segments[id]
		if !ok || s.WAN || (!s.Home && !slices.Contains(c.snapshot.GuestSegmentIDs, id)) || !defaultRouteInterface(s.Interface) || len(s.Prefixes) == 0 || len(s.Prefixes) > 16 {
			return dataplane.ErrReviewChanged
		}
		gate := DefaultRouteIngress{SegmentID: id, Interface: s.Interface}
		for _, prefix := range s.Prefixes {
			if !defaultRoutePrefix(prefix, false) {
				return dataplane.ErrReviewChanged
			}
		}
		gate.Sources = defaultRouteUniquePrefixes(s.Prefixes)
		if p.Clients.Mode == "selected_devices" || p.Clients.NewDevices == "base" {
			for deviceID, binding := range bindings {
				if binding.SegmentID != id || !binding.Confirmed || binding.Interface != s.Interface || p.Clients.Mode == "selected_devices" && !slices.Contains(p.Clients.DeviceIDs, deviceID) {
					continue
				}
				mac, _ := net.ParseMAC(binding.MAC) // validated above
				gate.IncludedMACs = append(gate.IncludedMACs, mac.String())
			}
			// An empty whitelist never becomes catch-all. Leave that segment
			// outside the compiled scope until a confirmed member is present.
			if len(gate.IncludedMACs) == 0 {
				continue
			}
		}
		negative, err := defaultRouteParsePrefixes(p.Clients.ExcludedCIDRs, false)
		if err != nil {
			return err
		}
		for _, deviceID := range p.Clients.ExcludedDeviceIDs {
			binding, ok := bindings[deviceID]
			mac, err := net.ParseMAC(binding.MAC)
			if !ok || !binding.Confirmed || err != nil || len(mac) != 6 || mac[0]&1 != 0 || mac.String() == "00:00:00:00:00:00" {
				return dataplane.ErrReviewChanged
			}
			if binding.SegmentID != id {
				continue
			}
			if binding.Interface != s.Interface {
				return dataplane.ErrReviewChanged
			}
			gate.ExcludedMACs = append(gate.ExcludedMACs, mac.String())
			for _, ip := range addresses[deviceID] {
				if !defaultRouteContains(s.Prefixes, ip) {
					return dataplane.ErrReviewChanged
				}
				negative = append(negative, netip.PrefixFrom(ip, ip.BitLen()))
			}
		}
		// Keep negatives as an early shared-owner gate. Splitting a /64 around
		// one excluded /128 and multiplying by all public destinations exceeds
		// small-router bounds, and still cannot exclude new device addresses.
		gate.Sources = defaultRouteUniquePrefixes(gate.Sources)
		gate.ExcludedSources = defaultRouteIntersections(gate.Sources, negative)
		slices.Sort(gate.IncludedMACs)
		slices.Sort(gate.ExcludedMACs)
		if len(gate.Sources) != 0 {
			c.ingress = append(c.ingress, gate)
		}
	}
	for _, id := range p.Clients.DeviceIDs {
		binding, ok := bindings[id]
		if !ok || !binding.Confirmed || !slices.Contains(p.Clients.SegmentIDs, binding.SegmentID) {
			return dataplane.ErrReviewChanged
		}
		segment, ok := segments[binding.SegmentID]
		if !ok || binding.Interface != segment.Interface {
			return dataplane.ErrReviewChanged
		}
	}
	// Source-only platform observations must not turn overlapping bridges
	// into an arbitrary choice of ingress. Same-bridge overlaps collapse.
	for i, a := range c.ingress {
		for _, b := range c.ingress[i+1:] {
			if a.Interface == b.Interface {
				return dataplane.ErrReviewChanged
			}
			for _, x := range a.Sources {
				for _, y := range b.Sources {
					if x.Overlaps(y) {
						return dataplane.ErrReviewChanged
					}
				}
			}
		}
	}
	sort.Slice(c.ingress, func(i, j int) bool { return c.ingress[i].SegmentID < c.ingress[j].SegmentID })
	return nil
}

func defaultRoutePublic(p *config.NetworkPolicy) ([]netip.Prefix, error) {
	// A conservative protected IP set is explicit compiler semantics. These
	// destinations continue through firmware policy, never a forced main rule.
	protected := []string{"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.168.0.0/16", "224.0.0.0/3", "::/128", "::1/128", "::ffff:0:0/96", "fc00::/7", "fe80::/10", "ff00::/8"}
	var excluded []netip.Prefix
	for _, v := range protected {
		excluded = append(excluded, netip.MustParsePrefix(v))
	}
	for _, r := range p.Rules {
		if r.Kind == "ip" {
			ip := netip.MustParseAddr(r.Value)
			excluded = append(excluded, netip.PrefixFrom(ip, ip.BitLen()))
		} else if r.Kind == "cidr" {
			excluded = append(excluded, netip.MustParsePrefix(r.Value))
		}
	}
	set, err := config.EffectiveResourceExclusions(p)
	if err != nil {
		return nil, err
	}
	for _, list := range [][]config.ResourceMatch{set.Manual, set.Russian} {
		for _, match := range list {
			switch match.Kind {
			case "ip":
				ip := netip.MustParseAddr(match.Value)
				excluded = append(excluded, netip.PrefixFrom(ip, ip.BitLen()))
			case "cidr":
				excluded = append(excluded, netip.MustParsePrefix(match.Value))
			}
		}
	}
	return defaultRouteSubtractPrefixes([]netip.Prefix{netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0")}, excluded)
}

func defaultRouteSubtractRule(a, b DefaultRouteRule) []DefaultRouteRule {
	if a.Ingress != b.Ingress || !a.Source.Overlaps(b.Source) || !a.Destination.Overlaps(b.Destination) {
		return []DefaultRouteRule{a}
	}
	var result []DefaultRouteRule
	for _, source := range defaultRouteSubtract(a.Source, b.Source) {
		r := a
		r.Source = source
		result = append(result, r)
	}
	source := a.Source
	if b.Source.Bits() > source.Bits() {
		source = b.Source
	}
	for _, destination := range defaultRouteSubtract(a.Destination, b.Destination) {
		r := a
		r.Source, r.Destination = source, destination
		result = append(result, r)
	}
	return result
}

func defaultRouteSubtract(a, b netip.Prefix) []netip.Prefix {
	if !a.Overlaps(b) {
		return []netip.Prefix{a}
	}
	if b.Bits() <= a.Bits() {
		return nil
	}
	left := netip.PrefixFrom(a.Addr(), a.Bits()+1)
	bytes := a.Addr().As16()
	bit := a.Bits()
	if a.Addr().Is4() {
		bit += 96
	}
	bytes[bit/8] |= 1 << (7 - bit%8)
	ip := netip.AddrFrom16(bytes)
	if a.Addr().Is4() {
		ip = ip.Unmap()
	}
	right := netip.PrefixFrom(ip, a.Bits()+1)
	return append(defaultRouteSubtract(left, b), defaultRouteSubtract(right, b)...)
}

func defaultRouteSubtractPrefixes(values, negative []netip.Prefix) ([]netip.Prefix, error) {
	for _, excluded := range negative {
		var next []netip.Prefix
		for _, prefix := range values {
			next = append(next, defaultRouteSubtract(prefix, excluded)...)
			if len(next) > defaultRouteRuleLimit {
				return nil, defaultRouteBound()
			}
		}
		values = next
	}
	return defaultRouteUniquePrefixes(values), nil
}

func defaultRouteIntersections(a, b []netip.Prefix) []netip.Prefix {
	var result []netip.Prefix
	for _, x := range a {
		for _, y := range b {
			if x.Overlaps(y) {
				if y.Bits() > x.Bits() {
					result = append(result, y)
				} else {
					result = append(result, x)
				}
			}
		}
	}
	return defaultRouteUniquePrefixes(result)
}

func defaultRouteUniquePrefixes(values []netip.Prefix) []netip.Prefix {
	values = slices.Clone(values)
	sort.Slice(values, func(i, j int) bool {
		if values[i].Bits() != values[j].Bits() {
			return values[i].Bits() < values[j].Bits()
		}
		return values[i].String() < values[j].String()
	})
	var result []netip.Prefix
	for _, prefix := range values {
		covered := false
		for _, existing := range result {
			if existing.Overlaps(prefix) && existing.Bits() <= prefix.Bits() {
				covered = true
				break
			}
		}
		if !covered {
			result = append(result, prefix)
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].String() < result[j].String() })
	return result
}

func defaultRouteParsePrefixes(values []string, destination bool) ([]netip.Prefix, error) {
	if len(values) > 256 {
		return nil, defaultRouteBound()
	}
	var result []netip.Prefix
	for _, value := range values {
		p, err := netip.ParsePrefix(value)
		if err != nil || !defaultRoutePrefix(p, destination) {
			return nil, fmt.Errorf("%w: invalid source/destination prefix", ErrDefaultRouteCapability)
		}
		result = append(result, p)
	}
	return defaultRouteUniquePrefixes(result), nil
}

func defaultRoutePrefix(p netip.Prefix, destination bool) bool {
	return p.IsValid() && p == p.Masked() && !p.Addr().Is4In6() && p.Addr().Zone() == "" && (destination || p.Bits() != 0 && p.Addr().IsGlobalUnicast())
}
func defaultRouteContains(prefixes []netip.Prefix, ip netip.Addr) bool {
	for _, p := range prefixes {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}
func defaultRouteInterface(v string) bool {
	return len(v) > 0 && len(v) <= 15 && v != "lo" && strings.Trim(v, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.:-") == ""
}
func defaultRoutePathValid(p DefaultRoutePath) bool {
	if strings.HasPrefix(p.Resolved, "wireguard:") || p.WireGuardProfileRevision != "" {
		if _, err := dataplane.FrozenWireGuardProfileRevision(dataplane.Route{Selected: p.Selected, Resolved: p.Resolved, WireGuardProfileRevision: p.WireGuardProfileRevision}); err != nil {
			return false
		}
	}
	return p.Selected != "" && p.Resolved != "" && dataplane.AdapterID(p.Resolved) != "" && p.Resolved != "direct" && defaultRouteHash(p.ProfileDigest) && defaultRouteHash(p.ProofDigest) && strings.HasPrefix(p.ProbeURL, "https://")
}
func defaultRouteHash(v string) bool {
	b, err := hex.DecodeString(v)
	return err == nil && len(b) == sha256.Size && v == strings.ToLower(v)
}
func defaultRouteDigest(v any) string {
	b, _ := json.Marshal(v)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
func defaultRouteBound() error {
	return fmt.Errorf("%w: expanded policy exceeds %d tuples", ErrDefaultRouteCapability, defaultRouteRuleLimit)
}
func defaultRouteRuleKey(r DefaultRouteRule) string {
	return r.Ingress + "\x00" + r.Source.String() + "\x00" + r.Destination.String() + "\x00" + r.ServiceID + "\x00" + r.Route
}

func defaultRouteCloneRoutes(routes []dataplane.Route) []dataplane.Route {
	result := slices.Clone(routes)
	for i := range result {
		r := &result[i]
		if r.ProbeService != nil {
			service := defaultRouteCloneCatalogService(*r.ProbeService)
			r.ProbeService = &service
		}
		r.Domains = slices.Clone(r.Domains)
		r.CIDRs = slices.Clone(r.CIDRs)
		r.Sources = slices.Clone(r.Sources)
		r.Ingress = slices.Clone(r.Ingress)
		r.SourceRefs = slices.Clone(r.SourceRefs)
	}
	return result
}

func defaultRouteCloneCatalogService(s catalog.Service) catalog.Service {
	s.Domains = slices.Clone(s.Domains)
	s.CIDRs = slices.Clone(s.CIDRs)
	s.Strategy = slices.Clone(s.Strategy)
	s.SourceRefs = slices.Clone(s.SourceRefs)
	s.Probes = slices.Clone(s.Probes)
	for i := range s.Probes {
		e := &s.Probes[i].Expect
		e.StatusCodes = slices.Clone(e.StatusCodes)
		e.RedirectHosts = slices.Clone(e.RedirectHosts)
		e.ContentTypes = slices.Clone(e.ContentTypes)
		e.JSONFields = slices.Clone(e.JSONFields)
		e.BodyContains = slices.Clone(e.BodyContains)
	}
	if s.Provenance != nil {
		p := *s.Provenance
		s.Provenance = &p
	}
	return s
}

func defaultRouteClone(s DefaultRouteSnapshot) DefaultRouteSnapshot {
	paths := s.Paths
	s.Scope.Segments = slices.Clone(s.Scope.Segments)
	for i := range s.Scope.Segments {
		s.Scope.Segments[i].Prefixes = slices.Clone(s.Scope.Segments[i].Prefixes)
	}
	s.Scope.Devices = slices.Clone(s.Scope.Devices)
	s.Devices = slices.Clone(s.Devices)
	for i := range s.Devices {
		s.Devices[i].Addresses = slices.Clone(s.Devices[i].Addresses)
	}
	s.GuestSegmentIDs = slices.Clone(s.GuestSegmentIDs)
	s.AllowedDefaultRoutes = slices.Clone(s.AllowedDefaultRoutes)
	s.Paths = make(map[string]DefaultRoutePath, len(s.Paths))
	for id, path := range paths {
		s.Paths[id] = path
	}
	return s
}

func defaultRouteIdentity(s DefaultRouteSnapshot) DefaultRouteSnapshot {
	paths := s.Paths
	s = defaultRouteClone(s)
	for id, path := range paths {
		s.Paths[id] = path
	}
	s.Scope.ObservedAt, s.Scope.FreshUntil = time.Time{}, time.Time{}
	slices.Sort(s.GuestSegmentIDs)
	slices.Sort(s.AllowedDefaultRoutes)
	sort.Slice(s.Scope.Segments, func(i, j int) bool { return s.Scope.Segments[i].ID < s.Scope.Segments[j].ID })
	for i := range s.Scope.Segments {
		s.Scope.Segments[i].Prefixes = defaultRouteUniquePrefixes(s.Scope.Segments[i].Prefixes)
	}
	sort.Slice(s.Scope.Devices, func(i, j int) bool { return s.Scope.Devices[i].ID < s.Scope.Devices[j].ID })
	for i := range s.Scope.Devices {
		if m, err := net.ParseMAC(s.Scope.Devices[i].MAC); err == nil {
			s.Scope.Devices[i].MAC = m.String()
		}
	}
	sort.Slice(s.Devices, func(i, j int) bool { return s.Devices[i].ID < s.Devices[j].ID })
	for i := range s.Devices {
		slices.SortFunc(s.Devices[i].Addresses, func(a, b netip.Addr) int { return a.Compare(b) })
		s.Devices[i].Addresses = slices.Compact(s.Devices[i].Addresses)
	}
	return s
}
