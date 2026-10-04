package dataplane

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/autonomy"
	"github.com/ArtixSx/razvilka/internal/config"
)

func domainPolicyFixture(t *testing.T, rules []config.NetworkRule) (*DomainPolicy, DomainPolicyFlow, time.Time) {
	t.Helper()
	now := time.Date(2026, 10, 4, 0, 0, 0, 0, time.UTC)
	policy := &config.NetworkPolicy{Schema: 2, Revision: 1, Clients: config.ClientScope{Mode: "lan_except", SegmentIDs: []string{"home"}, ExcludedDeviceIDs: []string{"excluded"}, NewDevices: "inherit"}, Traffic: config.TrafficSelection{Mode: "all_except", DefaultRoute: "wireguard", AllExceptAllowed: true, Unavailable: "block"}, Rules: rules}
	scope := autonomy.ScopeObservation{BootID: "boot", NetworkID: "network", Revision: 1, ObservedAt: now.Add(-time.Second), FreshUntil: now.Add(time.Minute), Segments: []autonomy.HomeSegment{{ID: "home", Interface: "br0", Home: true, Prefixes: []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24"), netip.MustParsePrefix("fd00:1::/64")}}}, Devices: []autonomy.DeviceBinding{{ID: "excluded", MAC: "02:00:00:00:00:01", Interface: "br0", SegmentID: "home", Confirmed: true}, {ID: "selected", MAC: "02:00:00:00:00:02", Interface: "br0", SegmentID: "home", Confirmed: true}}}
	services := []DomainPolicyService{{ID: "service", Route: "xray", Selected: true, Domains: []string{"service.example.com"}}}
	p, err := CompileDomainPolicy(strings.Repeat("a", 64), policy, scope, nil, services, now)
	if err != nil {
		t.Fatal(err)
	}
	f := DomainPolicyFlow{Client: autonomy.ClientPacket{Address: netip.MustParseAddr("192.168.1.42"), MAC: "02:00:00:00:00:02", Interface: "br0", SegmentID: "home"}, Destination: netip.MustParseAddr("93.184.215.14"), Protocol: "tcp", Name: "service.example.com", NameSource: "tls-sni", BeforeOutbound: true, DefaultCoverage: "supported"}
	return p, f, now
}

func TestDomainPolicySharedCDNUnknownAndLiteralFlowUseDefault(t *testing.T) {
	p, f, now := domainPolicyFixture(t, nil)
	if d := p.Decide(f, now); d.Kind != "service" || d.Route != "xray" {
		t.Fatal(d)
	}
	for name, mutate := range map[string]func(*DomainPolicyFlow){
		"same IP unknown name":            func(f *DomainPolicyFlow) { f.Name = "unknown.example.com" },
		"literal IP after service lookup": func(f *DomainPolicyFlow) { f.Name = ""; f.NameSource = "" },
		"one fresh DNS observation":       func(f *DomainPolicyFlow) { f.NameSource = "dns-observation" },
		"unverified fake IP":              func(f *DomainPolicyFlow) { f.NameSource = "fake-ip" },
		"ECH outer name":                  func(f *DomainPolicyFlow) { f.Ambiguous = true },
		"opaque UDP":                      func(f *DomainPolicyFlow) { f.Protocol = "udp"; f.NameSource = "" },
		"late TLS sniff":                  func(f *DomainPolicyFlow) { f.BeforeOutbound = false },
		"coalesced origins":               func(f *DomainPolicyFlow) { f.Coalesced = true },
	} {
		t.Run(name, func(t *testing.T) {
			flow := f
			mutate(&flow)
			if d := p.Decide(flow, now); d.Kind != "default" || d.Route != "wireguard" {
				t.Fatal(d)
			}
		})
	}
	p.services[0].Selected = false
	if d := p.Decide(f, now); d.Kind != "default" {
		t.Fatal("removed override became DIRECT", d)
	}
	p.services[0].Selected = true
	p.services[0].Sources = []string{"192.168.1.50/32"}
	if d := p.Decide(f, now); d.Kind != "default" {
		t.Fatal("override scope mismatch became DIRECT", d)
	}
}

func TestDomainPolicyDirectExclusionNeverWidensToSharedIP(t *testing.T) {
	rules := []config.NetworkRule{{ID: "manual-direct", Revision: 1, Kind: "exact", Value: "service.example.com", Action: "direct", Mandatory: true}}
	p, f, now := domainPolicyFixture(t, rules)
	if d := p.Decide(f, now); d.Kind != "baseline" || d.Reason != "MANUAL_DIRECT" {
		t.Fatal(d)
	}
	f.Name = "unknown.example.com"
	if d := p.Decide(f, now); d.Kind != "default" {
		t.Fatal("shared address inherited domain exclusion", d)
	}
	for _, source := range []string{"", "dns-observation", "fake-ip"} {
		f.Name = "service.example.com"
		f.NameSource = source
		if d := p.Decide(f, now); d.Kind != "refused" || d.Reason != "EXPLICIT_DOMAIN_DIRECT_REQUIRES_FLOW_IDENTITY" {
			t.Fatal("opaque explicit exclusion silently tunneled", d)
		}
	}
	// An explicit IP-wide exclusion is separate authority and remains usable.
	p.policy.Rules = append(p.policy.Rules, config.NetworkRule{ID: "ip-direct", Revision: 1, Kind: "ip", Value: f.Destination.String(), Action: "direct", Mandatory: true})
	if d := p.Decide(f, now); d.Kind != "baseline" {
		t.Fatal(d)
	}
}

func TestDomainPolicyIPDirectAndKnownMandatoryDomainBypassConflict(t *testing.T) {
	rules := []config.NetworkRule{
		{ID: "ip-direct", Revision: 1, Kind: "ip", Value: "93.184.215.14", Action: "direct", Mandatory: true},
		{ID: "domain-bypass", Revision: 1, Kind: "exact", Value: "service.example.com", Action: "bypass", Mandatory: true},
	}
	p, f, now := domainPolicyFixture(t, rules)
	if d := p.Decide(f, now); d.Kind != "refused" || d.Reason != "MANUAL_RULE_CONFLICT" || d.Decision.Action != "unavailable" {
		t.Fatal("IP direct bypassed known-name conflict", d)
	}
	called := false
	if d, err := p.Dispatch(context.Background(), f, now, func(context.Context, string) error { return nil }, func(context.Context, DomainPolicyDecision) error { called = true; return nil }); !errors.Is(err, ErrDomainPolicy) || d.Kind != "refused" || called {
		t.Fatal("conflicted known flow reached outbound", d, err, called)
	}
	for _, name := range []string{"", "unknown.example.com"} {
		f.Name = name
		if d := p.Decide(f, now); d.Kind != "baseline" || d.Reason != "MANUAL_DIRECT" {
			t.Fatal("explicit IP exclusion lost independent authority", name, d)
		}
	}
}

func TestDomainPolicyExcludedFuturePrivacyAddressAndGuestBeforeMetadata(t *testing.T) {
	p, f, now := domainPolicyFixture(t, nil)
	f.Client.Address = netip.MustParseAddr("fd00:1::ab:cdef")
	f.Client.MAC = "02:00:00:00:00:01"
	f.Name = "bad/name"
	if d := p.Decide(f, now); d.Kind != "outside" || d.Reason != "DEVICE_EXCLUDED" {
		t.Fatal(d)
	}
	f.Client.SegmentID = "guest"
	f.Client.Interface = "br-guest"
	if d := p.Decide(f, now); d.Kind != "outside" {
		t.Fatal(d)
	}
	called := false
	if d, err := p.Dispatch(context.Background(), f, now, func(context.Context, string) error { return nil }, func(context.Context, DomainPolicyDecision) error { called = true; return nil }); err != nil || d.Kind != "outside" || called {
		t.Fatal(d, err, called)
	}
}

func TestDomainPolicyFailedMatchedOutboundDoesNotFallback(t *testing.T) {
	p, f, now := domainPolicyFixture(t, nil)
	failure := errors.New("selected outbound failed")
	calls := 0
	d, err := p.Dispatch(context.Background(), f, now, func(context.Context, string) error { return nil }, func(_ context.Context, d DomainPolicyDecision) error {
		calls++
		if d.Kind != "service" || d.Route != "xray" {
			t.Fatal(d)
		}
		return failure
	})
	if !errors.Is(err, failure) || d.Kind != "failed" || d.Route != "xray" || calls != 1 {
		t.Fatal(d, err, calls)
	}
	calls = 0
	if _, err := p.Dispatch(context.Background(), f, now, func(context.Context, string) error { return ErrReviewChanged }, func(context.Context, DomainPolicyDecision) error { calls++; return nil }); !errors.Is(err, ErrReviewChanged) || calls != 0 {
		t.Fatal("stale generation dispatched", err, calls)
	}
}

func TestDomainPolicyOwnerScopeRefreshKeepsIdentityAndRejectsChangedBinding(t *testing.T) {
	p, f, now := domainPolicyFixture(t, nil)
	later := now.Add(3 * time.Minute)
	if d := p.Decide(f, later); d.Kind != "refused" {
		t.Fatal("expired review used")
	}
	current := cloneDomainPolicyScope(p.scope)
	current.ObservedAt = later.Add(-time.Second)
	current.FreshUntil = later.Add(time.Minute)
	if d := p.DecideWithScope(f, current, later); d.Kind != "service" {
		t.Fatal("same physical identity cannot renew observation", d)
	}
	current.Devices[0].MAC = "02:00:00:00:00:99"
	if d := p.DecideWithScope(f, current, later); d.Kind != "refused" || d.Reason != "SCOPE_IDENTITY_CHANGED" {
		t.Fatal(d)
	}
}
