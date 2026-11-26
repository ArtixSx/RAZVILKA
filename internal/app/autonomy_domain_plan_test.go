package app

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/autonomy"
	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/dnscontrol"
	"github.com/ArtixSx/razvilka/internal/nodestore"
)

func domainTCPPlanFixture() (config.Config, DefaultRouteSnapshot, catalog.Catalog, domainTCPProofRequest, time.Time) {
	now := time.Now().UTC()
	service := domainOriginalNativeService()
	cfg := config.Default()
	cfg.Revision = 1
	cfg.NetworkPolicy = &config.NetworkPolicy{
		Schema: 2, Revision: 1,
		Clients: config.ClientScope{Mode: "lan_except", SegmentIDs: []string{"home"}, NewDevices: "inherit", ExcludedDeviceIDs: []string{"excluded"}},
		Traffic: config.TrafficSelection{Mode: "selected_services", Unavailable: "block"},
	}
	cfg.Services[service.ID] = config.ServiceState{Enabled: true, Route: "auto"}
	client := netip.MustParseAddr("192.168.1.2")
	excluded := netip.MustParseAddr("192.168.1.3")
	observed := DefaultRouteSnapshot{
		Scope: autonomy.ScopeObservation{
			BootID: "boot", NetworkID: "network", Revision: 1, ObservedAt: now, FreshUntil: now.Add(time.Minute),
			Segments: []autonomy.HomeSegment{{ID: "home", Interface: "br0", Home: true, Prefixes: []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24")}}},
			Devices: []autonomy.DeviceBinding{
				{ID: "selected", MAC: "02:00:00:00:00:02", Interface: "br0", SegmentID: "home", Confirmed: true},
				{ID: "excluded", MAC: "02:00:00:00:00:03", Interface: "br0", SegmentID: "home", Confirmed: true},
			},
		},
		Devices: []DefaultRouteDevice{{ID: "selected", Addresses: []netip.Addr{client}}, {ID: "excluded", Addresses: []netip.Addr{excluded}}},
	}
	request := domainTCPProofRequest{
		ServiceID: service.ID, DeviceID: "selected", Client: client, NetworkProfile: "wan-0123456789ab", BaselineDNSProfile: "private", ServiceDNSProfile: "private",
		DNSListen: netip.MustParseAddrPort("192.168.1.1:10553"), CaptureListen: netip.MustParseAddrPort("192.168.1.1:10443"),
		Engine: dataplane.Engine{ID: "xray", Installed: true, Configured: true, Activatable: true, Canary: true},
		Host:   dataplane.HostState{IPCommand: true, IPTables: true, IP6Tables: true},
	}
	return cfg, observed, catalog.Catalog{Services: []catalog.Service{service}}, request, now
}

func TestDomainTCPProofPlanUsesOriginalOwners(t *testing.T) {
	cfg, observed, definitions, request, now := domainTCPPlanFixture()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	path := filepath.Join(t.TempDir(), "config.json")
	raw, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	store, err := config.LoadExisting(path)
	if err != nil {
		t.Fatal(err)
	}
	// Match the private node directory created by the installed application.
	nodesRoot := filepath.Join(t.TempDir(), "nodes")
	if err := os.Mkdir(nodesRoot, 0700); err != nil {
		t.Fatal(err)
	}
	nodes, err := nodestore.Open(nodesRoot)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = nodes.Close() })
	imported, err := nodes.Import(ctx, nodestore.Source{ID: "manual", Kind: "manual"}, "vless://e1293cc1-9a68-4dab-909a-45278631cb1c@203.0.113.42:443?security=tls&sni=front.example", now, time.Hour, false)
	if err != nil || len(imported.Nodes) != 1 {
		t.Fatalf("fixture import: %v", err)
	}
	source, err := dataplane.ReviewNodeDefaultSource(ctx, nodes, "xray:"+imported.Nodes[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	dns, err := dnscontrol.New("")
	if err != nil {
		t.Fatal(err)
	}
	exclusions, err := dnscontrol.NewNetworkPolicyDNSExclusions(ctx, store, store.Get(), func(context.Context, string) ([]string, error) { return []string{request.ServiceID}, nil })
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := prepareDomainTCPProofPlan(ctx, store, dns, exclusions, source, observed, definitions, request, now)
	if err != nil {
		t.Fatal(err)
	}
	domain, transport, err := prepared.plan.FrozenDomainTransport()
	if err != nil || prepared.plan.Ready || transport.Definition.Client != request.Client || len(transport.DNS.Bindings) != 1 || transport.DNS.Bindings[0].Domain != "service.example.com" || transport.DNS.Exclusions != exclusions.Stamp() {
		t.Fatalf("finite exact-name intent must stay blocked in ordinary Apply: %v", err)
	}
	if prepared.capture.Xray.NodeID != imported.Nodes[0].ID || prepared.capture.Xray.Generation != domain.Generation || prepared.capture.Xray.RealIP.IsValid() {
		t.Fatal("proof intent did not bind exact node identity, or already claims destination authority")
	}
	// A second persisted Store can have even the same full configuration.
	// Its negative observer must not be interchangeable with the original.
	copyPath := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(copyPath, raw, 0600); err != nil {
		t.Fatal(err)
	}
	copyStore, err := config.LoadExisting(copyPath)
	if err != nil {
		t.Fatal(err)
	}
	foreign, err := dnscontrol.NewNetworkPolicyDNSExclusions(ctx, copyStore, copyStore.Get(), func(context.Context, string) ([]string, error) {
		return nil, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if foreign.Stamp() != exclusions.Stamp() {
		t.Fatal("fixture must reproduce indistinguishable detached stamps")
	}
	if _, err := prepareDomainTCPProofPlan(ctx, store, dns, foreign, source, observed, definitions, request, now); !errors.Is(err, config.ErrRevisionChanged) {
		t.Fatalf("foreign DNS exclusion owner was accepted: %v", err)
	}
	// The named provider stays the same, while its endpoint identity changes.
	// Neither the old generation nor the old DNS plan may survive that change.
	request.ServiceDNSProfile = "nextdns"
	if err := dns.SetNextDNSProfileID("abcdef"); err != nil {
		t.Fatal(err)
	}
	first, err := prepareDomainTCPProofPlan(ctx, store, dns, exclusions, source, observed, definitions, request, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := dns.SetNextDNSProfileID("123456"); err != nil {
		t.Fatal(err)
	}
	second, err := prepareDomainTCPProofPlan(ctx, store, dns, exclusions, source, observed, definitions, request, now)
	if err != nil {
		t.Fatal(err)
	}
	firstDomain, firstTransport, err := first.plan.FrozenDomainTransport()
	if err != nil {
		t.Fatal(err)
	}
	secondDomain, secondTransport, err := second.plan.FrozenDomainTransport()
	if err != nil {
		t.Fatal(err)
	}
	if firstDomain.Generation == secondDomain.Generation || firstTransport.DNS.Bindings[0].ProfileDigest == secondTransport.DNS.Bindings[0].ProfileDigest {
		t.Fatal("provider edit reused the old domain generation")
	}
	if err := dns.CheckNetworkPolicyDNSPlan(ctx, firstTransport.DNS, exclusions); !errors.Is(err, dnscontrol.ErrServiceDNSChanged) {
		t.Fatalf("prior DNS review survived a provider edit: %v", err)
	}
	// A mode edit invalidates the original Store-bound DNS participation.
	manual := "manual"
	if err := store.UpdateServiceControl(&manual, nil, store.Get().Revision); err != nil {
		t.Fatal(err)
	}
	if _, err := prepareDomainTCPProofPlan(ctx, store, dns, exclusions, source, observed, definitions, request, now); !errors.Is(err, config.ErrRevisionChanged) {
		t.Fatalf("stale original DNS revision accepted: %v", err)
	}
}

func TestDomainTCPProofDefinitionPreservesExactScopeAndNegatives(t *testing.T) {
	reference := dataplane.NodeDefaultSourceReference{EngineID: "xray", NodeID: "node-test", Resolved: "xray:node-test"}
	for _, tc := range []struct {
		name   string
		change func(*config.Config, *DefaultRouteSnapshot, *catalog.Catalog, *domainTCPProofRequest)
		want   error
	}{
		{name: "standard covers an observed client"},
		{name: "standard covers a newly bound client without editing policy", change: func(_ *config.Config, observed *DefaultRouteSnapshot, _ *catalog.Catalog, request *domainTCPProofRequest) {
			request.DeviceID, request.Client = "new-client", netip.MustParseAddr("192.168.1.4")
			observed.Scope.Revision++
			observed.Scope.Devices = append(observed.Scope.Devices, autonomy.DeviceBinding{
				ID: request.DeviceID, MAC: "02:00:00:00:00:04", Interface: "br0", SegmentID: "home", Confirmed: true,
			})
			observed.Devices = append(observed.Devices, DefaultRouteDevice{ID: request.DeviceID, Addresses: []netip.Addr{request.Client}})
		}},
		{name: "selected devices allows designated client", change: func(cfg *config.Config, _ *DefaultRouteSnapshot, _ *catalog.Catalog, _ *domainTCPProofRequest) {
			cfg.NetworkPolicy.Clients.Mode, cfg.NetworkPolicy.Clients.NewDevices = "selected_devices", "base"
			cfg.NetworkPolicy.Clients.DeviceIDs = []string{"selected"}
		}},
		{name: "empty selected devices reach no client", change: func(cfg *config.Config, _ *DefaultRouteSnapshot, _ *catalog.Catalog, _ *domainTCPProofRequest) {
			cfg.NetworkPolicy.Clients.Mode, cfg.NetworkPolicy.Clients.NewDevices = "selected_devices", "base"
		}, want: errDomainProofIntent},
		{name: "selected service disabled", change: func(cfg *config.Config, _ *DefaultRouteSnapshot, _ *catalog.Catalog, request *domainTCPProofRequest) {
			delete(cfg.Services, request.ServiceID)
		}, want: errDomainProofIntent},
		{name: "stop prohibits a finite attempt", change: func(cfg *config.Config, _ *DefaultRouteSnapshot, _ *catalog.Catalog, _ *domainTCPProofRequest) {
			cfg.ServiceControl.Stopped = true
		}, want: errDomainProofIntent},
		{name: "another live assignment needs a composite executor", change: func(cfg *config.Config, _ *DefaultRouteSnapshot, _ *catalog.Catalog, _ *domainTCPProofRequest) {
			cfg.AppliedServices["other"] = config.ServiceState{Enabled: true, Route: "xray"}
		}, want: errDomainProofIntent},
		{name: "excluded device", change: func(_ *config.Config, observed *DefaultRouteSnapshot, _ *catalog.Catalog, request *domainTCPProofRequest) {
			request.DeviceID, request.Client = "excluded", observed.Devices[1].Addresses[0]
		}, want: errDomainProofScope},
		{name: "unobserved new client does not inherit proof authority", change: func(_ *config.Config, _ *DefaultRouteSnapshot, _ *catalog.Catalog, request *domainTCPProofRequest) {
			request.Client = netip.MustParseAddr("192.168.1.4")
		}, want: errDomainProofScope},
		{name: "duplicate lease", change: func(_ *config.Config, observed *DefaultRouteSnapshot, _ *catalog.Catalog, request *domainTCPProofRequest) {
			observed.Devices[1].Addresses = append(observed.Devices[1].Addresses, request.Client)
		}, want: errDomainProofScope},
		{name: "without bypass wins through an overlapping disabled identity", change: func(cfg *config.Config, _ *DefaultRouteSnapshot, definitions *catalog.Catalog, _ *domainTCPProofRequest) {
			blocked := definitions.Services[0]
			blocked.ID, blocked.Domains, blocked.ProbeURL, blocked.Probes = "blocked", []string{"example.com"}, "", nil
			definitions.Services = append(definitions.Services, blocked)
			cfg.NetworkPolicy.Rules = []config.NetworkRule{{ID: "without-bypass", Kind: "service", Value: "blocked", Action: "direct", Revision: 1, Mandatory: true}}
		}, want: errDomainProofScope},
		{name: "service source excludes client", change: func(cfg *config.Config, _ *DefaultRouteSnapshot, _ *catalog.Catalog, request *domainTCPProofRequest) {
			cfg.Services[request.ServiceID] = config.ServiceState{Enabled: true, Route: "auto", Sources: []string{"192.168.1.50/32"}}
		}, want: errDomainProofScope},
		{name: "multiple names cannot be reduced to a proof", change: func(_ *config.Config, _ *DefaultRouteSnapshot, definitions *catalog.Catalog, _ *domainTCPProofRequest) {
			definitions.Services[0].Domains = append(definitions.Services[0].Domains, "second.example.com")
		}, want: errDomainProofIntent},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, observed, definitions, request, now := domainTCPPlanFixture()
			if tc.change != nil {
				tc.change(&cfg, &observed, &definitions, &request)
			}
			plan, route, client, err := domainTCPProofDefinition(cfg, observed, definitions, request, reference, domainTCPDNSIdentity{}, now)
			if !errors.Is(err, tc.want) {
				t.Fatalf("expected %v, got %v", tc.want, err)
			}
			if err != nil {
				return
			}
			policy, err := dataplane.CompileDomainPolicy(plan.Generation, plan.Policy, plan.Scope, plan.GuestOptIn, plan.Services, now)
			if err != nil {
				t.Fatal(err)
			}
			flow := dataplane.DomainPolicyFlow{Client: client, Destination: netip.MustParseAddr("203.0.113.42"), Protocol: "tcp", Name: route.Domains[0], NameSource: "tls-sni", BeforeOutbound: true}
			if got := policy.Decide(flow, now); got.Kind != "service" || got.ServiceID != request.ServiceID || got.Route != reference.Resolved {
				t.Fatalf("exact selected flow was denied: %+v", got)
			}
			flow.Name = "other.example.com"
			if got := policy.Decide(flow, now); got.Kind != "baseline" {
				t.Fatalf("unselected name on the same address was captured: %+v", got)
			}
		})
	}
}

func TestDomainTCPProofGenerationTracksCandidateAndProbe(t *testing.T) {
	cfg, observed, definitions, request, now := domainTCPPlanFixture()
	first := dataplane.NodeDefaultSourceReference{EngineID: "xray", NodeID: "node-first", Resolved: "xray:node-first"}
	second := dataplane.NodeDefaultSourceReference{EngineID: "xray", NodeID: "node-second", Resolved: "xray:node-second"}
	compile := func(ref dataplane.NodeDefaultSourceReference) string {
		t.Helper()
		plan, route, _, err := domainTCPProofDefinition(cfg, observed, definitions, request, ref, domainTCPDNSIdentity{}, now)
		if err != nil || route.Resolved != ref.Resolved {
			t.Fatalf("node selection %q: %v", ref.Resolved, err)
		}
		return plan.Generation
	}
	before := compile(first)
	after := compile(second)
	if before == after {
		t.Fatal("replacement candidate reused the prior transport generation")
	}
	definitions.Services[0].Probes[0].Expect.BodyContains = []string{"new service response required"}
	if compile(second) == after {
		t.Fatal("changed service proof specification reused the prior generation")
	}
}
