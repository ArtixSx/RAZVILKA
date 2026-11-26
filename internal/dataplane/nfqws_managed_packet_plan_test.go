package dataplane

import (
	"context"
	"encoding/json"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/defaultconsent"
	"github.com/ArtixSx/razvilka/internal/netidentity"
	"github.com/ArtixSx/razvilka/internal/operationgate"
	"github.com/ArtixSx/razvilka/internal/physicalscope"
)

// Immutable comparison model only. It cannot construct original consent,
// packet scope, selected material or an executable native owner.
func nfqwsPacketInputFixture(t *testing.T) (Input, config.Config, defaultconsent.Reference, physicalscope.IPv4LANPacketFacts) {
	t.Helper()
	p := &config.NetworkPolicy{Schema: 2, Revision: 1, Clients: config.ClientScope{Mode: "lan_except", NewDevices: "inherit", SegmentIDs: []string{"Bridge0"}, ExcludedDeviceIDs: []string{"mac-02-00-00-00-00-55"}, ExcludedCIDRs: []string{"192.168.1.64/26"}}, Traffic: config.TrafficSelection{Mode: "selected_services", Unavailable: "retain"}}
	consent := &config.DefaultRouteConsent{Schema: 2, InstallationID: strings.Repeat("1", 32), Sequence: 1, ApprovalRevision: 3, ConfigRevision: 3, Policy: config.CloneNetworkPolicy(p)}
	consent.Digest = config.DefaultRouteConsentDigest(consent)
	cfg := config.Config{Revision: 3, Services: map[string]config.ServiceState{"listed": {Enabled: true, Route: "nfqws2"}}, NetworkPolicy: p, DefaultRouteConsent: consent}
	ref := defaultconsent.Reference{Schema: 1, InstallationID: consent.InstallationID, Sequence: 1, ApprovalRevision: 3, PolicyRevision: 1, ConsentDigest: consent.Digest}
	facts := physicalscope.IPv4LANPacketFacts{ScopeID: strings.Repeat("2", 32), Control: operationgate.ControlEpochReference{InstallationID: consent.InstallationID, Sequence: 1}, Intent: physicalscope.IPv4LANPacketIntent{Revision: 3, PolicyRevision: 1, Mode: "lan_except", NewDevices: "inherit", SegmentIDs: slices.Clone(p.Clients.SegmentIDs), ExcludedDeviceIDs: slices.Clone(p.Clients.ExcludedDeviceIDs), ExcludedCIDRs: slices.Clone(p.Clients.ExcludedCIDRs)}, Home: physicalscope.Segment{ID: "Bridge0", NativeName: "Home", Home: true, Interface: "br0", IfIndex: 3, Prefixes: []string{"192.168.1.0/24", "fd00::/64"}}, IPv4Prefixes: []string{"192.168.1.0/24"}, OwnedMACs: []string{"02:00:00:00:00:ff"}, OwnedAddresses: []string{"192.168.1.1", "fd00::1"}, ExcludedMACs: []string{"02:00:00:00:00:55"}}
	facts.Identity = netidentity.Identity{Version: 1, Kind: netidentity.ReviewedSingleInitNet, BootID: "12345678-1234-1234-1234-123456789abc", PlatformReviewSHA256: "f77d10cde0399faf1ab9ab6060bc52aa54e61e25c3d4c2381f4f712e78144733"}
	lan, err := CompileNFQWSDirectLANPolicyRuntime(strings.Repeat("a", 64), []LANPolicyIngress{{SegmentID: "Bridge0", Interface: "br0", Sources: []string{"192.168.1.0/24"}, ExcludedSources: []string{"192.168.1.1/32", "192.168.1.64/26"}, ExcludedMACs: []string{"02:00:00:00:00:55", "02:00:00:00:00:FF"}}})
	if err != nil {
		t.Fatal(err)
	}
	input := Input{Revision: 4, NetworkProfileID: "wan-123456789abc", LAN: lan, Routes: []Route{{ServiceID: "network-cell", LogicalServiceID: "listed", Selected: "nfqws2", Resolved: "nfqws2", NetworkPolicyRole: "override", NetworkPolicyGeneration: lan.Generation, Ingress: []string{"br0"}, Sources: []string{"192.168.1.0/24"}, CIDRs: []string{"203.0.113.0/25"}}}, Engines: []Engine{{ID: NetworkPolicyAdapterID, Installed: true, Configured: true, Activatable: true}, {ID: "nfqws2", Installed: true, Configured: true, Activatable: true}}}
	if !config.CurrentDefaultRouteScopeConsent(cfg) {
		t.Fatal("invalid comparison fixture")
	}
	return input, cfg, ref, facts
}

func TestNFQWSPacketIssuerRequiresOriginalOwners(t *testing.T) {
	input, cfg, _, _ := nfqwsPacketInputFixture(t)
	c, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	original := &NFQWSActiveMaterial{}
	original.self = original
	for _, m := range []*NFQWSActiveMaterial{nil, {}, original, {self: original}} {
		if p, err := BuildManagedNFQWSIPv4LANList(c, input, m, nil, nil, nil, cfg, time.Now()); err == nil || p.Ready {
			t.Fatal("comparison-only DTO became full Home grant", err)
		}
	}
}

func TestNFQWSPacketIssuerComparisonRefusesCompositesAndWidening(t *testing.T) {
	input, cfg, ref, facts := nfqwsPacketInputFixture(t)
	if err := nfqwsIPv4LANPacketInput(input, cfg, ref, facts, "listed", "tcp", "ipv4"); err != nil {
		t.Fatal("exact comparison refused", err)
	}
	type image struct {
		Input Input
		Cfg   config.Config
		Ref   defaultconsent.Reference
		Facts physicalscope.IPv4LANPacketFacts
	}
	raw, err := json.Marshal(image{input, cfg, ref, facts})
	if err != nil {
		t.Fatal(err)
	}
	for name, edit := range map[string]func(*image){
		"domain":                func(i *image) { i.Input.Routes[0].Domains = []string{"example.com"} },
		"DNS":                   func(i *image) { i.Input.DNS = &ScopedDNSPlan{} },
		"domain policy":         func(i *image) { i.Input.DomainPolicy = &DomainPolicyRuntimePlan{} },
		"synthetic DNS":         func(i *image) { i.Input.SyntheticDNS = &SyntheticDNSTransportPlan{} },
		"suspend DNS":           func(i *image) { i.Input.SuspendDNS = true },
		"discard DNS":           func(i *image) { i.Input.DiscardDNS = true },
		"retire other adapter":  func(i *image) { i.Input.RetiringAdapters = []string{"wireguard"} },
		"draft other adapter":   func(i *image) { i.Input.EngineConfigDrafts = []string{"wireguard"} },
		"other participant":     func(i *image) { i.Input.Engines = append(i.Input.Engines, Engine{ID: "wireguard"}) },
		"source reference":      func(i *image) { i.Input.Routes[0].SourceRefs = []string{"community:x"} },
		"safe mode":             func(i *image) { i.Input.SafeMode = true },
		"missing WAN":           func(i *image) { i.Input.NetworkProfileID = "" },
		"hash is not WAN token": func(i *image) { i.Input.NetworkProfileID = strings.Repeat("b", 64) },
		"unknown WAN":           func(i *image) { i.Input.NetworkProfileID = "network-unknown" },
		"approval changed":      func(i *image) { i.Ref.ApprovalRevision++ },
		"sequence changed":      func(i *image) { i.Facts.Control.Sequence++ },
		"different policy":      func(i *image) { i.Facts.Intent.PolicyRevision++ },
		"legacy selected source": func(i *image) {
			v := i.Cfg.Services["listed"]
			v.Sources = []string{"192.168.1.40/32"}
			i.Cfg.Services["listed"] = v
		},
		"wider source":        func(i *image) { i.Input.Routes[0].Sources = []string{"192.168.0.0/16"} },
		"empty source":        func(i *image) { i.Input.Routes[0].Sources = nil },
		"foreign ingress":     func(i *image) { i.Input.Routes[0].Ingress = []string{"br1"} },
		"IPv6":                func(i *image) { i.Input.Routes[0].CIDRs = []string{"2001:db8::/32"} },
		"multicast":           func(i *image) { i.Input.Routes[0].CIDRs = []string{"224.0.0.0/4"} },
		"private":             func(i *image) { i.Input.Routes[0].CIDRs = []string{"192.168.1.0/24"} },
		"zero destinations":   func(i *image) { i.Input.Routes[0].CIDRs = nil },
		"second route":        func(i *image) { i.Input.Routes = append(i.Input.Routes, i.Input.Routes[0]) },
		"lost offline MAC":    func(i *image) { i.Input.LAN.Ingress[0].ExcludedMACs = []string{"02:00:00:00:00:FF"} },
		"lost own source":     func(i *image) { i.Input.LAN.Ingress[0].ExcludedSources = []string{"192.168.1.64/26"} },
		"lost exclusion CIDR": func(i *image) { i.Input.LAN.Ingress[0].ExcludedSources = []string{"192.168.1.1/32"} },
		"manual IP gap lost": func(i *image) {
			i.Cfg.NetworkPolicy.Exclusions = &config.ResourceExclusions{Schema: 1, Revision: 1, Manual: []config.ResourceMatch{{Kind: "ip", Value: "203.0.113.10"}}}
		},
		"domain exclusion": func(i *image) {
			i.Cfg.NetworkPolicy.Exclusions = &config.ResourceExclusions{Schema: 1, Revision: 1, Manual: []config.ResourceMatch{{Kind: "exact", Value: "example.com"}}}
		},
		"service exclusion": func(i *image) {
			i.Cfg.NetworkPolicy.Exclusions = &config.ResourceExclusions{Schema: 1, Revision: 1, Manual: []config.ResourceMatch{{Kind: "service", Value: "listed"}}}
		},
		"legacy direct exclusion lost": func(i *image) {
			i.Cfg.NetworkPolicy.Rules = []config.NetworkRule{{ID: "negative", Revision: 1, Kind: "ip", Value: "203.0.113.10", Action: "direct", Mandatory: true}}
		},
		"legacy device-specific negative": func(i *image) {
			i.Cfg.NetworkPolicy.Rules = []config.NetworkRule{{ID: "negative", Revision: 1, Kind: "ip", Value: "203.0.113.10", Action: "direct", Mandatory: true, DeviceIDs: []string{"some-device"}}}
		},
	} {
		t.Run(name, func(t *testing.T) {
			var i image
			if err := json.Unmarshal(raw, &i); err != nil {
				t.Fatal(err)
			}
			edit(&i)
			if i.Input.LAN != nil {
				lan, err := CompileNFQWSDirectLANPolicyRuntime(i.Input.LAN.Generation, i.Input.LAN.Ingress)
				if err == nil {
					i.Input.LAN = lan
				}
			}
			if err := nfqwsIPv4LANPacketInput(i.Input, i.Cfg, i.Ref, i.Facts, "listed", "tcp", "ipv4"); err == nil {
				t.Fatal("composite/widened scope comparison accepted")
			}
		})
	}
	for _, pair := range [][2]string{{"quic", "ipv4"}, {"tcp", "ipv6"}, {"udp", "ipv4"}} {
		if err := nfqwsIPv4LANPacketInput(input, cfg, ref, facts, "listed", pair[0], pair[1]); err == nil {
			t.Fatal("unsupported selected material accepted", pair)
		}
	}
}

func TestNFQWSPacketIssuerKeepsCanonicalCoveringSourceNegative(t *testing.T) {
	input, cfg, ref, f := nfqwsPacketInputFixture(t)
	cfg.NetworkPolicy.Clients.ExcludedCIDRs = []string{"192.168.1.0/26"}
	cfg.DefaultRouteConsent.Policy = config.CloneNetworkPolicy(cfg.NetworkPolicy)
	cfg.DefaultRouteConsent.Digest = config.DefaultRouteConsentDigest(cfg.DefaultRouteConsent)
	ref.ConsentDigest = cfg.DefaultRouteConsent.Digest
	f.Intent.ExcludedCIDRs = slices.Clone(cfg.NetworkPolicy.Clients.ExcludedCIDRs)
	input.LAN.Ingress[0].ExcludedSources = []string{"192.168.1.0/26"}
	var err error
	input.LAN, err = CompileNFQWSDirectLANPolicyRuntime(input.LAN.Generation, input.LAN.Ingress)
	if err != nil {
		t.Fatal(err)
	}
	if err = nfqwsIPv4LANPacketInput(input, cfg, ref, f, "listed", "tcp", "ipv4"); err != nil {
		t.Fatal("covered own /32 negative was incorrectly required separately", err)
	}
}

func TestNFQWSLegacyManagedIssuerRemainsHostOnly(t *testing.T) {
	input, _, _, _ := nfqwsPacketInputFixture(t)
	if managedNFQWSHostRoutes(input, "listed") == nil {
		t.Fatal("legacy issuer accepted Home/24")
	}
	input.Routes[0].Sources = []string{"192.168.1.40/32"}
	if managedNFQWSHostRoutes(input, "listed") == nil {
		t.Fatal("legacy issuer accepted destination CIDR")
	}
	input.Routes[0].CIDRs = []string{"203.0.113.10/32"}
	if err := managedNFQWSHostRoutes(input, "listed"); err != nil {
		t.Fatal("legacy exact host boundary changed", err)
	}
}

func TestNFQWSPacketDirectEffectsOnlyCaptureExactHomeTCPAndPreserveForeignBaseline(t *testing.T) {
	input, cfg, ref, facts := nfqwsPacketInputFixture(t)
	if err := nfqwsIPv4LANPacketInput(input, cfg, ref, facts, "listed", "tcp", "ipv4"); err != nil {
		t.Fatal(err)
	}
	_, spec, _ := nfqwsScopedFixture(t)
	spec.Candidate.ServiceID, spec.Candidate.IPFamily = "listed", "ipv4"
	spec.Candidate.Traffic = []NFQWSScopedTraffic{{Protocol: "tcp", First: 443, Last: 443}}
	spec.Matches = []NFQWSScopedMatch{{ServiceID: "listed", Origin: "override", Route: "nfqws2", Ingress: "br0", Source: netip.MustParsePrefix("192.168.1.0/24"), Destination: netip.MustParsePrefix("203.0.113.0/25"), Protocol: "tcp", FirstPort: 443, LastPort: 443}}
	plan := Plan{SchemaVersion: SchemaVersion, Ready: true, PlanID: "packet-model", Digest: strings.Repeat("c", 64), Revision: input.Revision, NetworkProfileID: input.NetworkProfileID, Routes: input.Routes, LAN: input.LAN}
	p, err := CompileNFQWSScopedPlan(plan, spec)
	if err != nil {
		t.Fatal(err)
	}
	effects, err := p.Effects()
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range effects.Effects {
		line := strings.Join(e.Add, " ")
		if e.Tool != PolicyEffectIPTables || strings.Contains(line, "MARK") || strings.Contains(line, "--mark") || strings.Contains(line, "-t nat") || strings.Contains(line, "OUTPUT") || strings.Contains(line, "--queue-bypass") {
			t.Fatal("direct mode changed routing/DNS/other hooks", line)
		}
	}
	flow := nfqwsDirectFlow{hook: "FORWARD", ingress: "br0", source: "192.168.1.200", destination: "203.0.113.10", mac: "02:00:00:00:00:99", protocol: "tcp", port: 443, mark: 0x40000000}
	// A nonzero native owner-VPN mark still retains its value. Our modeled
	// selector queues only exact positives and creates no ip-rule/main override.
	if !nfqwsDirectCaptures(t, p, flow) {
		t.Fatal("unseen Home endpoint not captured")
	}
	for _, edit := range []func(*nfqwsDirectFlow){func(f *nfqwsDirectFlow) { f.mac = "02:00:00:00:00:55" }, func(f *nfqwsDirectFlow) { f.mac = "02:00:00:00:00:ff" }, func(f *nfqwsDirectFlow) { f.source = "192.168.1.1" }, func(f *nfqwsDirectFlow) { f.source = "192.168.1.70" }, func(f *nfqwsDirectFlow) { f.destination = "203.0.113.200" }, func(f *nfqwsDirectFlow) { f.destination = "8.8.8.8" }, func(f *nfqwsDirectFlow) { f.protocol = "udp" }, func(f *nfqwsDirectFlow) { f.port = 80 }, func(f *nfqwsDirectFlow) { f.ingress = "br1" }, func(f *nfqwsDirectFlow) { f.hook = "OUTPUT" }} {
		f := flow
		edit(&f)
		if nfqwsDirectCaptures(t, p, f) {
			t.Fatal("negative/unmatched flow changed native baseline", f)
		}
	}
}
