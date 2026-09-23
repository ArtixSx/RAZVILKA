package autonomy

import (
	"net/netip"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/config"
)

func scopeFixture() (*config.NetworkPolicy, ScopeObservation, TrafficQuestion, time.Time) {
	now := time.Date(2026, 9, 23, 12, 0, 0, 0, time.UTC)
	p := &config.NetworkPolicy{Schema: 1, Revision: 1, Clients: config.ClientScope{Mode: "lan_except", SegmentIDs: []string{"home"}, ExcludedDeviceIDs: []string{"laptop"}, NewDevices: "inherit"}, Traffic: config.TrafficSelection{Mode: "selected_services", Unavailable: "retain"}}
	o := ScopeObservation{BootID: "boot", NetworkID: "network", Revision: 3, ObservedAt: now.Add(-time.Second), FreshUntil: now.Add(time.Minute), Segments: []HomeSegment{{ID: "home", Interface: "br0", Home: true, Prefixes: []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24"), netip.MustParsePrefix("fd00:1::/64")}}}, Devices: []DeviceBinding{{ID: "laptop", MAC: "02:00:00:00:00:01", Interface: "br0", SegmentID: "home", Confirmed: true}, {ID: "phone", MAC: "02:00:00:00:00:02", Interface: "br0", SegmentID: "home", Confirmed: true}}}
	q := TrafficQuestion{Client: ClientPacket{Address: netip.MustParseAddr("192.168.1.40"), MAC: "02:00:00:00:00:02", Interface: "br0", SegmentID: "home"}, Domain: "example.ru", ServiceID: "bank", ServiceSelected: true}
	return p, o, q, now
}

func TestNetworkScopeKeepsNegativeIdentityAcrossDHCPAndIPv6(t *testing.T) {
	tests := []struct {
		name, action, reason string
		change               func(*config.NetworkPolicy, *ScopeObservation, *TrafficQuestion)
	}{
		{"selected service", "bypass", "DEFAULT_POLICY", func(p *config.NetworkPolicy, o *ScopeObservation, q *TrafficQuestion) {}},
		{"unknown site", "base", "UNSELECTED_DESTINATION", func(p *config.NetworkPolicy, o *ScopeObservation, q *TrafficQuestion) { q.ServiceSelected = false }},
		{"excluded MAC", "base", "DEVICE_EXCLUDED", func(p *config.NetworkPolicy, o *ScopeObservation, q *TrafficQuestion) {
			q.Client.MAC = o.Devices[0].MAC
		}},
		{"excluded new IPv4", "base", "DEVICE_EXCLUDED", func(p *config.NetworkPolicy, o *ScopeObservation, q *TrafficQuestion) {
			q.Client.MAC = o.Devices[0].MAC
			q.Client.Address = netip.MustParseAddr("192.168.1.90")
		}},
		{"excluded IPv6", "base", "DEVICE_EXCLUDED", func(p *config.NetworkPolicy, o *ScopeObservation, q *TrafficQuestion) {
			q.Client.MAC = o.Devices[0].MAC
			q.Client.Address = netip.MustParseAddr("fd00:1::abcd")
		}},
		{"new owner of old IPv4", "bypass", "DEFAULT_POLICY", func(p *config.NetworkPolicy, o *ScopeObservation, q *TrafficQuestion) {
			q.Client.MAC = "02:00:00:00:00:03"
		}},
		{"missing excluded binding", "unavailable", "SCOPE_UNAVAILABLE", func(p *config.NetworkPolicy, o *ScopeObservation, q *TrafficQuestion) { o.Devices = o.Devices[1:] }},
		{"offline excluded binding", "unavailable", "SCOPE_UNAVAILABLE", func(p *config.NetworkPolicy, o *ScopeObservation, q *TrafficQuestion) { o.Devices[0].Confirmed = false }},
		{"excluded wrong interface", "unavailable", "SCOPE_UNAVAILABLE", func(p *config.NetworkPolicy, o *ScopeObservation, q *TrafficQuestion) { o.Devices[0].Interface = "wan" }},
		{"bad excluded MAC", "unavailable", "SCOPE_UNAVAILABLE", func(p *config.NetworkPolicy, o *ScopeObservation, q *TrafficQuestion) {
			o.Devices[0].MAC = "00:00:00:00:00:00"
		}},
		{"EUI64 is not client MAC", "unavailable", "SCOPE_UNAVAILABLE", func(p *config.NetworkPolicy, o *ScopeObservation, q *TrafficQuestion) {
			o.Devices[0].MAC = "02:00:00:00:00:00:00:01"
		}},
		{"missing client discriminator", "unavailable", "SCOPE_UNAVAILABLE", func(p *config.NetworkPolicy, o *ScopeObservation, q *TrafficQuestion) { q.Client.MAC = "" }},
		{"guest not inherited", "base", "OUTSIDE_SCOPE", func(p *config.NetworkPolicy, o *ScopeObservation, q *TrafficQuestion) { q.Client.SegmentID = "guest" }},
		{"WAN never home", "unavailable", "SCOPE_UNAVAILABLE", func(p *config.NetworkPolicy, o *ScopeObservation, q *TrafficQuestion) { o.Segments[0].WAN = true }},
		{"other prefix", "base", "OUTSIDE_SCOPE", func(p *config.NetworkPolicy, o *ScopeObservation, q *TrafficQuestion) {
			q.Client.Address = netip.MustParseAddr("192.168.2.40")
		}},
		{"positive service cannot expand home", "base", "OUTSIDE_SCOPE", func(p *config.NetworkPolicy, o *ScopeObservation, q *TrafficQuestion) {
			q.Client.SegmentID = "guest"
			q.ServiceSources = []string{"192.168.0.0/16"}
		}},
		{"positive service intersects", "base", "SERVICE_SCOPE_MISMATCH", func(p *config.NetworkPolicy, o *ScopeObservation, q *TrafficQuestion) {
			q.ServiceSources = []string{"192.168.1.41/32"}
		}},
		{"IPv6 CIDR exclusion", "base", "ADDRESS_EXCLUDED", func(p *config.NetworkPolicy, o *ScopeObservation, q *TrafficQuestion) {
			p.Clients.ExcludedCIDRs = []string{"fd00:1::/64"}
			q.Client.Address = netip.MustParseAddr("fd00:1::2")
		}},
		{"new client base policy", "base", "OUTSIDE_SCOPE", func(p *config.NetworkPolicy, o *ScopeObservation, q *TrafficQuestion) {
			p.Clients.NewDevices = "base"
			q.Client.MAC = "02:00:00:00:00:03"
		}},
		{"selected devices", "base", "OUTSIDE_SCOPE", func(p *config.NetworkPolicy, o *ScopeObservation, q *TrafficQuestion) {
			p.Clients.Mode = "selected_devices"
			p.Clients.NewDevices = "base"
			p.Clients.DeviceIDs = []string{"laptop"}
		}},
		{"stale scope", "unavailable", "SCOPE_UNAVAILABLE", func(p *config.NetworkPolicy, o *ScopeObservation, q *TrafficQuestion) { o.FreshUntil = o.ObservedAt }},
		{"unknown other segment does not block home", "bypass", "DEFAULT_POLICY", func(p *config.NetworkPolicy, o *ScopeObservation, q *TrafficQuestion) {
			o.Devices[0].SegmentID = "guest"
			o.Devices[0].Confirmed = false
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, o, q, now := scopeFixture()
			tt.change(p, &o, &q)
			d := DecideNetworkPolicy(p, o, q, now)
			if d.Action != tt.action || d.Reason != tt.reason {
				t.Fatalf("got %+v", d)
			}
		})
	}
}

func TestNetworkPolicyPrioritiesAndExplicitRussianOverride(t *testing.T) {
	p, o, q, now := scopeFixture()
	p.Russian = config.RussianExclusions{Enabled: true, CatalogID: "ru-curated", Revision: 4, Digest: strings.Repeat("a", 64), ServiceIDs: []string{"bank"}}
	assert := func(reason string) {
		t.Helper()
		d := DecideNetworkPolicy(p, o, q, now)
		if d.Reason != reason {
			t.Fatalf("want %s got %+v", reason, d)
		}
	}
	assert("RU_CATALOG_DIRECT") // merely enabling a service does not override RU
	q.ExplicitBypass = true
	assert("MANUAL_BYPASS_OVERRIDE")
	p.Rules = []config.NetworkRule{{ID: "direct", Revision: 1, Kind: "suffix", Value: "example.ru", Action: "direct", Mandatory: true}}
	assert("MANUAL_DIRECT")
	q.ProtectedDestination = true
	assert("PROTECTED_DESTINATION")
	q.ProtectedDestination = false
	q.Client.MAC = o.Devices[0].MAC
	assert("DEVICE_EXCLUDED")
	q.Client.MAC = o.Devices[1].MAC
	p.Rules = nil
	q.ExplicitBypass = false
	q.ServiceID = "other"
	assert("DEFAULT_POLICY") // .ru itself is not curated
	p.Russian.BroadTLDs = []string{"ru"}
	assert("RU_CATALOG_DIRECT")
	q.Domain = "example.ru.attacker.test"
	assert("DEFAULT_POLICY")
	p.Russian.BroadTLDs = nil
	q.ServiceSelected = false
	assert("UNSELECTED_DESTINATION")
	p.Traffic = config.TrafficSelection{Mode: "all_except", AllExceptAllowed: true, DefaultRoute: "usque", Unavailable: "retain"}
	assert("DEFAULT_POLICY")
	// DNS can reveal a conflict between a domain and a literal-IP rule that
	// could not be determined from domain strings alone at config validation.
	q.Domain = "example.ru"
	q.Address = netip.MustParseAddr("203.0.113.1")
	p.Rules = []config.NetworkRule{{ID: "direct", Revision: 1, Kind: "exact", Value: q.Domain, Action: "direct", Mandatory: true}, {ID: "bypass", Revision: 1, Kind: "ip", Value: q.Address.String(), Action: "bypass", Mandatory: true}}
	assert("MANUAL_RULE_CONFLICT")
}

func TestNetworkScopeDigestStableOnFreshObservation(t *testing.T) {
	p, o, q, now := scopeFixture()
	before := DecideNetworkPolicy(p, o, q, now)
	original := config.CloneNetworkPolicy(p)
	devices := slices.Clone(o.Devices)
	o.ObservedAt = o.ObservedAt.Add(time.Second)
	o.FreshUntil = o.FreshUntil.Add(time.Second)
	slices.Reverse(o.Devices)
	slices.Reverse(o.Segments[0].Prefixes)
	renewed := DecideNetworkPolicy(p, o, q, now)
	if len(before.ScopeDigest) != 64 || before.ScopeDigest != renewed.ScopeDigest {
		t.Fatalf("refresh changed identity: %+v %+v", before, renewed)
	}
	if !reflect.DeepEqual(original, p) || !reflect.DeepEqual(o.Devices[0], devices[1]) {
		t.Fatal("digest mutated caller state")
	}
	o.BootID = "reboot"
	if DecideNetworkPolicy(p, o, q, now).ScopeDigest == before.ScopeDigest {
		t.Fatal("reboot reused identity")
	}
	o.BootID = "boot"
	p.Revision++
	if DecideNetworkPolicy(p, o, q, now).ScopeDigest == before.ScopeDigest {
		t.Fatal("new policy reused identity")
	}
}

func TestSharedAddressConflictUsesOverlappingClientsNotDigestEquality(t *testing.T) {
	a := AddressDecision{Interface: "br0", Sources: []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24")}, Address: netip.MustParseAddr("203.0.113.1"), Domain: "bank.ru", Action: "base"}
	b := AddressDecision{Interface: "br0", Sources: []netip.Prefix{netip.MustParsePrefix("192.168.1.40/32")}, Address: a.Address, Domain: "other.example", Action: "bypass"}
	if !SharedAddressConflict([]AddressDecision{a, b}) {
		t.Fatal("overlapping source prefixes lost conflict")
	}
	b.Interface = "br1"
	if SharedAddressConflict([]AddressDecision{a, b}) {
		t.Fatal("isolated interfaces collided")
	}
	b.Interface = "br0"
	a.MAC = "02:00:00:00:00:01"
	b.MAC = "02:00:00:00:00:02"
	if SharedAddressConflict([]AddressDecision{a, b}) {
		t.Fatal("separate packet discriminators collided")
	}
	b.MAC = ""
	if !SharedAddressConflict([]AddressDecision{a, b}) {
		t.Fatal("catchall did not overlap excluded client")
	}
	b.Sources = []netip.Prefix{netip.MustParsePrefix("192.168.2.0/24")}
	if SharedAddressConflict([]AddressDecision{a, b}) {
		t.Fatal("separate prefixes collided")
	}
	b.Sources = nil
	if !SharedAddressConflict([]AddressDecision{b}) {
		t.Fatal("missing sources accepted as universal")
	}
	a.Sources = []netip.Prefix{netip.MustParsePrefix("fd00:1::/64")}
	b.Sources = []netip.Prefix{netip.MustParsePrefix("fd00:1::abcd/128")}
	if !SharedAddressConflict([]AddressDecision{a, b}) {
		t.Fatal("IPv6 conflict missed")
	}
	many := make([]AddressDecision, 257)
	for i := range many {
		many[i] = a
	}
	if !SharedAddressConflict(many) {
		t.Fatal("unbounded shared address accepted")
	}
}
