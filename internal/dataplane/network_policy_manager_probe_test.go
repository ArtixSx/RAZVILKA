package dataplane

import (
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/catalog"
)

func networkPolicyProbeFixture() Route {
	s := catalog.Service{ID: "example", Name: "Example", Category: "test", Strategy: []string{"xray"},
		Domains: []string{"example.com"}, ProbeURL: "https://example.com/status", SourceRefs: []string{"catalog-source"},
		Provenance: &catalog.Provenance{Provider: "trusted"},
		Probes: []catalog.Probe{{ID: "status", Label: "Status", URL: "https://example.com/status", Required: true,
			Expect: catalog.ProbeExpectation{StatusCodes: []int{200}, RedirectPolicy: "allowlist", RedirectHosts: []string{"example.com"},
				ContentTypes: []string{"application/json"}, JSON: true, JSONFields: []string{"ready"}, BodyContains: []string{"ready"}}}},
	}
	return Route{ServiceID: "network-cell", LogicalServiceID: s.ID, ProbeService: &s, ProbeURL: s.ProbeURL,
		Resolved: "xray:home", Sources: []string{"192.168.1.0/24"}, Ingress: []string{"br0"}, CIDRs: []string{"8.8.8.0/24"},
		NetworkPolicyGeneration: strings.Repeat("a", 64), NetworkPolicyRole: "override"}
}

func TestNetworkPolicyManagerFrozenProbeIdentityAndCopies(t *testing.T) {
	route := networkPolicyProbeFixture()
	plan, err := BuildAt(Input{Routes: []Route{route}}, time.Unix(100, 0))
	if err != nil {
		t.Fatal(err)
	}
	route.ProbeService.Probes[0].Expect.BodyContains[0] = "changed"
	route.ProbeService.Provenance.Provider = "changed"
	scoped := plan.RoutePlanFor("xray")
	service, err := FrozenProbeService(scoped.Routes[0])
	if err != nil || service.ID != "example" || service.Probes[0].Expect.BodyContains[0] != "ready" || service.Provenance.Provider != "trusted" {
		t.Fatalf("frozen catalog semantics lost: %+v, %v", service, err)
	}
	service.Probes[0].Expect.JSONFields[0] = "changed"
	scoped.Routes[0].ProbeService.Probes[0].Expect.StatusCodes[0] = 204
	full, err := FrozenProbeService(plan.Routes[0])
	if err != nil || full.Probes[0].Expect.JSONFields[0] != "ready" || full.Probes[0].Expect.StatusCodes[0] != 200 {
		t.Fatal("returned or scoped service aliased full plan", err)
	}
	changed := networkPolicyProbeFixture()
	changed.ProbeService.Probes[0].Expect.BodyContains[0] = "different"
	other, err := BuildAt(Input{Routes: []Route{changed}}, time.Unix(100, 0))
	if err != nil || other.Digest == plan.Digest {
		t.Fatal("full service semantics missing from plan seal", err)
	}
}

func TestNetworkPolicyManagerProbeRefusesMissingOrDifferentCatalog(t *testing.T) {
	cases := map[string]func(*Route){
		"missing":                   func(r *Route) { r.ProbeService = nil },
		"scalar synthetic identity": func(r *Route) { r.LogicalServiceID = "" },
		"other service":             func(r *Route) { r.LogicalServiceID = "other" },
		"other URL":                 func(r *Route) { r.ProbeURL = "https://example.com/other" },
		"default transport":         func(r *Route) { r.NetworkPolicyRole = "default"; r.LogicalServiceID = "default" },
		"ambiguous scenario": func(r *Route) {
			p := r.ProbeService.Probes[0]
			p.ID = "second"
			r.ProbeService.Probes = append(r.ProbeService.Probes, p)
		},
		"unbounded":         func(r *Route) { r.ProbeService.Note = strings.Repeat("x", 65<<10) },
		"invalid semantics": func(r *Route) { r.ProbeService.Probes[0].Expect.JSON = false },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			route := networkPolicyProbeFixture()
			mutate(&route)
			if _, err := FrozenProbeService(route); err == nil {
				t.Fatal("missing/mismatched semantics accepted")
			}
			if route.ProbeService != nil {
				if _, err := BuildAt(Input{Routes: []Route{route}}, time.Unix(100, 0)); err == nil {
					t.Fatal("invalid provided predicate accepted by Build")
				}
			}
		})
	}
	legacy := networkPolicyProbeFixture()
	legacy.NetworkPolicyGeneration, legacy.NetworkPolicyRole, legacy.LogicalServiceID = "", "", ""
	legacy.ServiceID = legacy.ProbeService.ID
	if _, err := FrozenProbeService(legacy); err != nil {
		t.Fatal("legacy logical identity unavailable", err)
	}
}
