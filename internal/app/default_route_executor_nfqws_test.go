package app

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/strategylab"
)

// Detached comparison models exercise only pure compilation. They neither
// issue an original source review nor prove native compatibility or launch.
func defaultRouteNFQWSComparisonFixture(protocol, family string) (config.Config, DefaultRouteSnapshot, []dataplane.Route, time.Time) {
	cfg, snapshot, now := defaultRouteFixture()
	cfg.Services["listed"] = config.ServiceState{Enabled: true, Route: "nfqws2"}
	routes := defaultRouteListedRoutes()
	routes[0].Selected, routes[0].Resolved, routes[0].WireGuardProfileRevision = "nfqws2", "nfqws2", ""
	transport := protocol
	if protocol == "quic" {
		transport = "udp"
	}
	reference := strategylab.SelectedCandidateReference{
		ServiceID: "listed", Protocol: protocol, IPFamily: family, CandidateID: "candidate-listed",
		Incarnation: strings.Repeat("b", 32), ReceiptID: strings.Repeat("c", 32),
		ManifestSHA256: strings.Repeat("1", 64), SelectionDigest: strings.Repeat("2", 64),
		SourceDigest: strings.Repeat("3", 64), CompatibilityDigest: strings.Repeat("4", 64), MaterialDigest: strings.Repeat("5", 64),
		Arguments: []string{"--filter-" + transport + "=443"},
		Traffic:   []strategylab.SelectedCandidateTraffic{{Protocol: transport, IPFamily: family, First: 443, Last: 443}},
	}
	reference.ArgumentsDigest, reference.TrafficDigest = defaultRouteDigest(reference.Arguments), defaultRouteDigest(reference.Traffic)
	snapshot.Paths["listed"] = DefaultRoutePath{Selected: "nfqws2", Resolved: "nfqws2", ProbeURL: "https://example.com/", NFQWS: &reference}
	snapshot.ProfileGeneration = 0
	return cfg, snapshot, routes, now
}

func TestDefaultRouteNFQWSComparisonRestrictsTransportPortAndFamily(t *testing.T) {
	for _, selection := range []struct{ protocol, family, transport string }{{"tcp", "ipv4", "tcp"}, {"quic", "ipv6", "udp"}} {
		t.Run(selection.protocol+"-"+selection.family, func(t *testing.T) {
			cfg, snapshot, routes, now := defaultRouteNFQWSComparisonFixture(selection.protocol, selection.family)
			compiled, err := CompileDefaultRoutePolicy(cfg, snapshot, routes, now)
			if err != nil || len(compiled.Rules()) == 0 {
				t.Fatal("exact detached comparison was not compiled", err)
			}
			for _, rule := range compiled.Rules() {
				if rule.Protocol != selection.transport || rule.FirstPort != 443 || rule.LastPort != 443 || rule.Source.Addr().Is4() != (selection.family == "ipv4") || rule.Destination.Addr().Is4() != rule.Source.Addr().Is4() {
					t.Fatal("source traffic coverage widened", rule)
				}
			}
			for _, flow := range []DefaultRouteFlow{defaultRouteFlow("192.168.1.40", "203.0.113.40"), defaultRouteFlow("fd00::40", "2001:db8::40")} {
				for _, transport := range []string{"", "tcp", "udp"} {
					for _, port := range []uint16{0, 80, 442, 443, 444} {
						flow.Protocol, flow.DestinationPort = transport, port
						decision := compiled.Classify(flow)
						matches := transport == selection.transport && port == 443 && flow.Source.Is4() == (selection.family == "ipv4")
						if matches && (decision.Kind != DefaultRouteOverride || decision.Route != "nfqws2") || !matches && (decision.Kind != DefaultRouteBaseline || decision.Route != "") {
							t.Fatal("unproved traffic changed routing", flow, decision)
						}
					}
				}
			}
		})
	}
}

func TestDefaultRouteNFQWSComparisonRequiresExactSourceAndNoSurrogate(t *testing.T) {
	for name, change := range map[string]func(*DefaultRoutePath){
		"missing":            func(p *DefaultRoutePath) { p.NFQWS = nil },
		"foreign-service":    func(p *DefaultRoutePath) { p.NFQWS.ServiceID = "other" },
		"missing-source":     func(p *DefaultRoutePath) { p.NFQWS.SourceDigest = "" },
		"missing-completion": func(p *DefaultRoutePath) { p.NFQWS.CompatibilityDigest = "" },
		"missing-material":   func(p *DefaultRoutePath) { p.NFQWS.MaterialDigest = "" },
		"foreign-family":     func(p *DefaultRoutePath) { p.NFQWS.Traffic[0].IPFamily = "ipv6" },
		"foreign-transport":  func(p *DefaultRoutePath) { p.NFQWS.Traffic[0].Protocol = "udp" },
		"changed-port":       func(p *DefaultRoutePath) { p.NFQWS.Traffic[0].Last = 444 },
		"changed-arguments":  func(p *DefaultRoutePath) { p.NFQWS.Arguments[0] = "--filter-tcp=80" },
		"profile-surrogate":  func(p *DefaultRoutePath) { p.ProfileDigest = strings.Repeat("6", 64) },
		"proof-surrogate":    func(p *DefaultRoutePath) { p.ProofDigest = strings.Repeat("7", 64) },
		"foreign-path":       func(p *DefaultRoutePath) { p.Resolved = "warp-wg" },
	} {
		t.Run(name, func(t *testing.T) {
			cfg, snapshot, routes, now := defaultRouteNFQWSComparisonFixture("tcp", "ipv4")
			path := snapshot.Paths["listed"]
			change(&path)
			snapshot.Paths["listed"] = path
			if _, err := CompileDefaultRoutePolicy(cfg, snapshot, routes, now); err == nil {
				t.Fatal("incomplete comparison or invented surrogate accepted")
			}
		})
	}
	cfg, snapshot, routes, now := defaultRouteNFQWSComparisonFixture("tcp", "ipv4")
	cfg.Services["other"] = cfg.Services["listed"]
	other := routes[0]
	other.ServiceID = "other"
	routes = append(routes, other)
	path := snapshot.Paths["listed"]
	path.NFQWS = defaultRouteCloneNFQWSReference(path.NFQWS)
	path.NFQWS.ServiceID = "other"
	snapshot.Paths["other"] = path
	if _, err := CompileDefaultRoutePolicy(cfg, snapshot, routes, now); !errors.Is(err, ErrDefaultRouteCapability) {
		t.Fatal("singleton NFQUEUE spec accepted multiple service bindings", err)
	}
	cfg, snapshot, now = defaultRouteFixture()
	snapshot.ProfileGeneration = 0
	if _, err := CompileDefaultRoutePolicy(cfg, snapshot, defaultRouteListedRoutes(), now); !errors.Is(err, dataplane.ErrReviewChanged) {
		t.Fatal("tunnel path borrowed the NFQWS exemption from profile generation", err)
	}
}

func TestDefaultRouteNFQWSComparisonCopiesIdentityAndKeepsNegativesFirst(t *testing.T) {
	cfg, snapshot, routes, now := defaultRouteNFQWSComparisonFixture("tcp", "ipv4")
	cfg.NetworkPolicy.Exclusions = &config.ResourceExclusions{Schema: 1, Revision: 1, Manual: []config.ResourceMatch{{Kind: "cidr", Value: "203.0.113.0/25"}}}
	compiled, err := CompileDefaultRoutePolicy(cfg, snapshot, routes, now)
	if err != nil {
		t.Fatal(err)
	}
	before, ok := compiled.NFQWSReference("listed")
	if !ok {
		t.Fatal("compiled positive has no source comparison")
	}
	snapshot.Paths["listed"].NFQWS.Arguments[0] = "--filter-tcp=80"
	snapshot.Paths["listed"].NFQWS.Traffic[0].First = 80
	copy, _ := compiled.NFQWSReference("listed")
	copy.Arguments[0], copy.Traffic[0].First = "--filter-tcp=81", 81
	after, _ := compiled.NFQWSReference("listed")
	if !reflect.DeepEqual(before, after) {
		t.Fatal("source comparison aliases caller or accessor slices")
	}
	flow := defaultRouteFlow("192.168.1.40", "203.0.113.40")
	flow.Protocol, flow.DestinationPort = "tcp", 443
	if decision := compiled.Classify(flow); decision.Kind != DefaultRouteExcluded || decision.Route != "" {
		t.Fatal("negative destination reached NFQUEUE", decision)
	}
	flow.Destination = defaultRouteFlow("192.168.1.40", "203.0.113.200").Destination
	if compiled.Classify(flow).Kind != DefaultRouteOverride {
		t.Fatal("remaining literal CIDR positive lost")
	}
	_, changed, changedRoutes, _ := defaultRouteNFQWSComparisonFixture("tcp", "ipv4")
	changed.Paths["listed"].NFQWS.SourceDigest = strings.Repeat("8", 64)
	other, err := CompileDefaultRoutePolicy(cfg, changed, changedRoutes, now)
	if err != nil || other.Digest() == compiled.Digest() {
		t.Fatal("exact saved source image did not change review identity", err)
	}
}

func TestDefaultRouteNFQWSOriginalReferenceAndGenericConsumerStayClosed(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	for _, original := range []*strategylab.SelectedCandidateReview{nil, {}} {
		if reference, err := defaultRouteNFQWSReference(ctx, original); err == nil || reference.CandidateID != "" {
			t.Fatal("unissued original source became an authority", reference, err)
		}
	}
	defaultRouteRequireLinuxJournal(t)
	cfg, snapshot, routes, _ := defaultRouteNFQWSComparisonFixture("tcp", "ipv4")
	e, _, adapter := defaultRouteExecutorFixtureConfig(t, cfg, snapshot)
	before := e.app.Store.Get()
	if _, err := e.Review(context.Background(), routes); !errors.Is(err, ErrDefaultRouteCapability) || !strings.Contains(err.Error(), "exact traffic consumer") || len(adapter.steps) != 0 || !reflect.DeepEqual(before, e.app.Store.Get()) {
		t.Fatal("generic route lost exact NFQWS traffic coverage", err, adapter.steps)
	}
}
