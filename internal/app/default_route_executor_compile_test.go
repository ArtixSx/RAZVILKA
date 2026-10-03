package app

import (
	"errors"
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/autonomy"
	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/dataplane"
)

func defaultRouteFixture() (config.Config, DefaultRouteSnapshot, time.Time) {
	now := time.Now()
	cfg := config.Default()
	cfg.SafeMode, cfg.Revision = false, 8
	cfg.NetworkPolicy = &config.NetworkPolicy{Schema: 2, Revision: 1,
		Clients: config.ClientScope{Mode: "lan_except", SegmentIDs: []string{"home"}, NewDevices: "inherit"},
		Traffic: config.TrafficSelection{Mode: "all_except", DefaultRoute: "wireguard", AllExceptAllowed: true, Unavailable: "retain"}}
	snapshot := DefaultRouteSnapshot{Scope: autonomy.ScopeObservation{BootID: "boot-current", NetworkID: "wan-111111111111", Revision: 2, ObservedAt: now.Add(-time.Second), FreshUntil: now.Add(time.Minute),
		Segments: []autonomy.HomeSegment{{ID: "home", Interface: "br0", Home: true, Prefixes: []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24"), netip.MustParsePrefix("fd00::/64")}}},
		Devices:  []autonomy.DeviceBinding{{ID: "included", MAC: "02:00:00:00:00:01", Interface: "br0", SegmentID: "home", Confirmed: true}, {ID: "excluded", MAC: "02:00:00:00:00:02", Interface: "br0", SegmentID: "home", Confirmed: true}}},
		Devices:           []DefaultRouteDevice{{ID: "included", Addresses: []netip.Addr{netip.MustParseAddr("192.168.1.40"), netip.MustParseAddr("fd00::40")}}, {ID: "excluded", Addresses: []netip.Addr{netip.MustParseAddr("192.168.1.50"), netip.MustParseAddr("fd00::50")}}},
		Paths:             map[string]DefaultRoutePath{"default": {Selected: "wireguard", Resolved: "wireguard:reserve", ProfileDigest: strings.Repeat("1", 64), ProofDigest: strings.Repeat("2", 64), ProbeURL: "https://example.com/"}},
		ProfileGeneration: 1, Authority: DefaultRouteAuthority{InstallationID: "installation-current", Sequence: 5, ConsentDigest: strings.Repeat("3", 64)}, AllowedDefaultRoutes: []string{"wireguard"}, DNSMode: "baseline"}
	return cfg, snapshot, now
}

func defaultRouteOverrideFixture(cfg *config.Config, snapshot *DefaultRouteSnapshot) []dataplane.Route {
	cfg.Services["service"] = config.ServiceState{Enabled: true, Route: "warp-wg", Sources: []string{"192.168.1.40/32", "fd00::40/128"}}
	snapshot.Paths["service"] = DefaultRoutePath{Selected: "warp-wg", Resolved: "warp-wg", ProfileDigest: strings.Repeat("4", 64), ProofDigest: strings.Repeat("5", 64), ProbeURL: "https://example.org/"}
	return []dataplane.Route{{ServiceID: "service", ServiceName: "Service", Selected: "warp-wg", Resolved: "warp-wg", CIDRs: []string{"203.0.113.0/24", "2001:db8:1234::/48"}, Sources: []string{"192.168.1.40/32", "fd00::40/128"}}}
}

func defaultRouteFlow(source, destination string) DefaultRouteFlow {
	return DefaultRouteFlow{Ingress: "br0", Source: netip.MustParseAddr(source), Destination: netip.MustParseAddr(destination), MAC: "02:00:00:00:00:01"}
}

func TestDefaultRouteNoServicesUnknownAndDirectIP(t *testing.T) {
	cfg, snapshot, now := defaultRouteFixture()
	c, err := CompileDefaultRoutePolicy(cfg, snapshot, nil, now)
	if err != nil {
		t.Fatal(err)
	}
	for _, flow := range []DefaultRouteFlow{defaultRouteFlow("192.168.1.40", "203.0.113.40"), defaultRouteFlow("fd00::40", "2001:db8::40")} {
		for _, name := range []string{"", "unknown.example.com", "service.example.com"} {
			flow.FlowName, flow.DNSObservedName = name, "service.example.com"
			d := c.Classify(flow)
			if d.Kind != DefaultRouteDefault || d.Route != "wireguard:reserve" || d.ServiceID != "default" {
				t.Fatalf("flow=%+v decision=%+v", flow, d)
			}
		}
	}
	for _, destination := range []string{"192.168.2.3", "127.0.0.1", "169.254.1.2", "224.0.0.1", "fd01::3", "fe80::1", "::1", "ff02::1"} {
		source := "192.168.1.40"
		if strings.Contains(destination, ":") {
			source = "fd00::40"
		}
		if c.Classify(defaultRouteFlow(source, destination)).Kind != DefaultRouteExcluded {
			t.Fatal("protected destination captured", destination)
		}
	}
	for i, a := range c.rules {
		for _, b := range c.rules[i+1:] {
			if a.Ingress == b.Ingress && a.Source.Overlaps(b.Source) && a.Destination.Overlaps(b.Destination) {
				t.Fatalf("overlap %+v %+v", a, b)
			}
		}
	}
	if len(c.rules) > defaultRouteRuleLimit {
		t.Fatal("unbounded default")
	}
}

func TestDefaultRouteAutoRequiresConcreteConsentAndProof(t *testing.T) {
	cfg, s, now := defaultRouteFixture()
	cfg.NetworkPolicy.Traffic.DefaultRoute = config.DefaultRouteAuto
	path := s.Paths["default"]
	path.Selected = config.DefaultRouteAuto
	s.Paths["default"] = path
	c, err := CompileDefaultRoutePolicy(cfg, s, nil, now)
	if err != nil || c.Policy().Traffic.DefaultRoute != "wireguard" || cfg.NetworkPolicy.Traffic.DefaultRoute != config.DefaultRouteAuto {
		t.Fatal("auto did not resolve without editing desired intent", err)
	}
	s.AllowedDefaultRoutes = []string{config.DefaultRouteAuto}
	if _, err := CompileDefaultRoutePolicy(cfg, s, nil, now); err == nil {
		t.Fatal("auto intent granted concrete default consent")
	}
}

func TestDefaultRouteOverrideScopeMissRemovalAndFailure(t *testing.T) {
	cfg, snapshot, now := defaultRouteFixture()
	routes := defaultRouteOverrideFixture(&cfg, &snapshot)
	c, err := CompileDefaultRoutePolicy(cfg, snapshot, routes, now)
	if err != nil {
		t.Fatal(err)
	}
	for _, source := range []string{"192.168.1.40", "fd00::40"} {
		destination := "203.0.113.9"
		if strings.Contains(source, ":") {
			destination = "2001:db8:1234::9"
		}
		d := c.Classify(defaultRouteFlow(source, destination))
		if d.Kind != DefaultRouteOverride || d.Route != "warp-wg" {
			t.Fatalf("override=%+v", d)
		}
		failed := d.Failed()
		if failed.Kind != DefaultRouteFailed || failed.Route != d.Route || failed.Generation != d.Generation {
			t.Fatal("execution failure became miss/default")
		}
		other := "192.168.1.41"
		if strings.Contains(source, ":") {
			other = "fd00::41"
		}
		if c.Classify(defaultRouteFlow(other, destination)).Kind != DefaultRouteDefault {
			t.Fatal("service scope miss did not continue default")
		}
	}
	delete(cfg.Services, "service")
	removed, err := CompileDefaultRoutePolicy(cfg, snapshot, routes, now)
	if err != nil {
		t.Fatal(err)
	}
	if removed.Classify(defaultRouteFlow("192.168.1.40", "203.0.113.9")).Kind != DefaultRouteDefault {
		t.Fatal("removed override became direct")
	}
	if removed.digest == c.digest {
		t.Fatal("removed override reused generation")
	}
	for i, a := range c.rules {
		for _, b := range c.rules[i+1:] {
			if a.Ingress == b.Ingress && a.Source.Overlaps(b.Source) && a.Destination.Overlaps(b.Destination) {
				t.Fatalf("default/override overlap %+v %+v", a, b)
			}
		}
	}
}

func TestDefaultRouteExcludedDevicesSitesAndGuestOptIn(t *testing.T) {
	cfg, snapshot, now := defaultRouteFixture()
	cfg.NetworkPolicy.Clients.ExcludedDeviceIDs = []string{"excluded"}
	cfg.NetworkPolicy.Rules = []config.NetworkRule{{ID: "site", Revision: 1, Kind: "cidr", Value: "203.0.113.0/24", Action: "direct", Mandatory: true}}
	routes := defaultRouteOverrideFixture(&cfg, &snapshot)
	c, err := CompileDefaultRoutePolicy(cfg, snapshot, routes, now)
	if err != nil {
		t.Fatal(err)
	}
	for _, flow := range []DefaultRouteFlow{defaultRouteFlow("192.168.1.50", "198.51.100.1"), defaultRouteFlow("fd00::50", "2001:db8::1"), defaultRouteFlow("192.168.1.40", "203.0.113.1")} {
		if c.Classify(flow).Kind != DefaultRouteExcluded {
			t.Fatal("excluded source/site reached owned path", flow)
		}
	}
	// New privacy addresses and spoofed included IPs cannot bypass MAC negative.
	flow := defaultRouteFlow("fd00::9876", "2001:db8::1")
	flow.MAC = "02:00:00:00:00:02"
	if c.Classify(flow).Kind != DefaultRouteExcluded {
		t.Fatal("excluded MAC with new address captured")
	}
	flow = defaultRouteFlow("192.168.1.40", "198.51.100.1")
	flow.Ingress = "guest0"
	if c.Classify(flow).Kind != DefaultRouteOutside {
		t.Fatal("unselected guest captured")
	}
	snapshot.Scope.Segments[0].Home = false
	if _, err := CompileDefaultRoutePolicy(cfg, snapshot, routes, now); err == nil {
		t.Fatal("guest implicitly opted in")
	}
	snapshot.GuestSegmentIDs = []string{"home"}
	if _, err := CompileDefaultRoutePolicy(cfg, snapshot, routes, now); err != nil {
		t.Fatal("explicit guest opt-in refused", err)
	}
	if len(c.rules) >= defaultRouteRuleLimit {
		t.Fatal("negative device caused prefix explosion")
	}
}

func TestDefaultRouteSelectedDevicesAndNewDevicesBase(t *testing.T) {
	for _, mode := range []string{"selected_devices", "lan_except"} {
		cfg, snapshot, now := defaultRouteFixture()
		cfg.NetworkPolicy.Clients.Mode, cfg.NetworkPolicy.Clients.NewDevices = mode, "base"
		if mode == "selected_devices" {
			cfg.NetworkPolicy.Clients.DeviceIDs = []string{"included"}
		}
		c, err := CompileDefaultRoutePolicy(cfg, snapshot, nil, now)
		if err != nil {
			t.Fatal(err)
		}
		if c.Classify(defaultRouteFlow("192.168.1.40", "203.0.113.1")).Kind != DefaultRouteDefault {
			t.Fatal("confirmed included device missing")
		}
		if c.Classify(defaultRouteFlow("192.168.1.99", "203.0.113.1")).Kind != DefaultRouteOutside {
			t.Fatal("new device inherited without consent")
		}
	}
}

func TestDefaultRouteRefusesUnavailableAndAmbiguousInputs(t *testing.T) {
	for name, mutate := range map[string]func(*config.Config, *DefaultRouteSnapshot){
		"safe mode":        func(c *config.Config, _ *DefaultRouteSnapshot) { c.SafeMode = true },
		"stop":             func(c *config.Config, _ *DefaultRouteSnapshot) { c.ServiceControl.Stopped = true },
		"durable stop":     func(_ *config.Config, s *DefaultRouteSnapshot) { s.Stopped = true },
		"expired":          func(_ *config.Config, s *DefaultRouteSnapshot) { s.Scope.FreshUntil = s.Scope.ObservedAt },
		"missing consent":  func(_ *config.Config, s *DefaultRouteSnapshot) { s.AllowedDefaultRoutes = nil },
		"missing control":  func(_ *config.Config, s *DefaultRouteSnapshot) { s.Authority.InstallationID = "" },
		"missing profile":  func(_ *config.Config, s *DefaultRouteSnapshot) { s.Paths = nil },
		"auto unresolved":  func(c *config.Config, _ *DefaultRouteSnapshot) { c.NetworkPolicy.Traffic.DefaultRoute = "auto" },
		"wan":              func(_ *config.Config, s *DefaultRouteSnapshot) { s.Scope.Segments[0].WAN = true },
		"wildcard ingress": func(_ *config.Config, s *DefaultRouteSnapshot) { s.Scope.Segments[0].Interface = "br+" },
		"unresolved negative": func(c *config.Config, _ *DefaultRouteSnapshot) {
			c.NetworkPolicy.Clients.ExcludedDeviceIDs = []string{"unknown"}
		},
		"dns not implemented": func(_ *config.Config, s *DefaultRouteSnapshot) { s.DNSMode = "default-tunnel" },
		"domain exclusion": func(c *config.Config, _ *DefaultRouteSnapshot) {
			c.NetworkPolicy.Rules = []config.NetworkRule{{ID: "site", Revision: 1, Kind: "exact", Value: "example.com", Mandatory: true, Action: "direct"}}
		},
		"overlapping ingress": func(_ *config.Config, s *DefaultRouteSnapshot) {
			other := s.Scope.Segments[0]
			other.ID, other.Interface = "second", "br1"
			s.Scope.Segments = append(s.Scope.Segments, other)
		},
	} {
		t.Run(name, func(t *testing.T) {
			cfg, s, now := defaultRouteFixture()
			mutate(&cfg, &s)
			if name == "overlapping ingress" {
				cfg.NetworkPolicy.Clients.SegmentIDs = append(cfg.NetworkPolicy.Clients.SegmentIDs, "second")
			}
			if _, err := CompileDefaultRoutePolicy(cfg, s, nil, now); err == nil {
				t.Fatal("unsafe input accepted")
			}
		})
	}
	cfg, s, now := defaultRouteFixture()
	routes := defaultRouteOverrideFixture(&cfg, &s)
	routes[0].Domains = []string{"service.example.com"}
	if _, err := CompileDefaultRoutePolicy(cfg, s, routes, now); !errors.Is(err, ErrDefaultRouteCapability) {
		t.Fatal("DNS IP map became domain capability", err)
	}
}

func TestDefaultRouteReviewIdentityAndDefensiveCopies(t *testing.T) {
	cfg, s, now := defaultRouteFixture()
	c, err := CompileDefaultRoutePolicy(cfg, s, nil, now)
	if err != nil {
		t.Fatal(err)
	}
	refreshed := defaultRouteClone(s)
	refreshed.Scope.ObservedAt, refreshed.Scope.FreshUntil = now, now.Add(time.Minute)
	slicesReverseDefaultRoute(refreshed.Scope.Segments[0].Prefixes)
	renewed, err := CompileDefaultRoutePolicy(cfg, refreshed, nil, now)
	if err != nil || renewed.digest != c.digest {
		t.Fatal("renewed unchanged scope changed identity", err)
	}
	for name, mutate := range map[string]func(*DefaultRouteSnapshot){
		"network": func(s *DefaultRouteSnapshot) { s.Scope.NetworkID = "wan-222222222222" },
		"scope":   func(s *DefaultRouteSnapshot) { s.Scope.Revision++ },
		"epoch":   func(s *DefaultRouteSnapshot) { s.Authority.Sequence++ },
		"consent": func(s *DefaultRouteSnapshot) { s.Authority.ConsentDigest = strings.Repeat("6", 64) },
		"profile": func(s *DefaultRouteSnapshot) { s.ProfileGeneration++ },
		"node":    func(s *DefaultRouteSnapshot) { s.NodeGeneration++ },
	} {
		t.Run(name, func(t *testing.T) {
			changed := defaultRouteClone(s)
			mutate(&changed)
			other, err := CompileDefaultRoutePolicy(cfg, changed, nil, now)
			if err != nil || other.digest == c.digest {
				t.Fatal("changed authority reused review", err)
			}
		})
	}
	before := c.Rules()
	s.Scope.Segments[0].Prefixes[0] = netip.MustParsePrefix("10.0.0.0/8")
	s.Paths["default"] = DefaultRoutePath{}
	p := c.Policy()
	p.Clients.SegmentIDs[0] = "changed"
	gates := c.Ingress()
	gates[0].Sources[0] = netip.MustParsePrefix("10.0.0.0/8")
	rules := c.Rules()
	rules[0].Route = "direct"
	if !reflect.DeepEqual(before, c.Rules()) || c.policy.Clients.SegmentIDs[0] != "home" || c.snapshot.Paths["default"].Resolved != "wireguard:reserve" {
		t.Fatal("caller edited reviewed execution")
	}
}

func slicesReverseDefaultRoute[T any](values []T) {
	for i, j := 0, len(values)-1; i < j; i, j = i+1, j-1 {
		values[i], values[j] = values[j], values[i]
	}
}

func TestDefaultRoutePrefixSubtractionExhaustiveIPv4AndIPv6(t *testing.T) {
	for _, base := range []string{"192.168.1.0/28", "fd00::/124"} {
		prefix := netip.MustParsePrefix(base)
		var ips []netip.Addr
		for ip := prefix.Addr(); prefix.Contains(ip); ip = ip.Next() {
			ips = append(ips, ip)
		}
		for _, excluded := range ips {
			remaining := defaultRouteSubtract(prefix, netip.PrefixFrom(excluded, excluded.BitLen()))
			for _, ip := range ips {
				if defaultRouteContains(remaining, ip) != (ip != excluded) {
					t.Fatalf("base %s exclusion %s address %s", base, excluded, ip)
				}
			}
		}
	}
}
