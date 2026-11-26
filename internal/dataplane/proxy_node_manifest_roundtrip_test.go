package dataplane

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/catalog"
)

func compiledScopedManifestFixture(t *testing.T, namedProbe bool) (*scopedXrayFixture, string) {
	t.Helper()
	f := scopedXrayTestFixture(t)
	r := &f.plan.Routes[0]
	r.Domains, r.CIDRs = nil, []string{"8.8.8.8/32"}
	r.LogicalServiceID = r.ServiceID
	r.ProbeService = &catalog.Service{ID: r.ServiceID, Name: r.ServiceName, Category: "internet",
		Domains: []string{"telegram.org"}, Strategy: []string{"xray", "sing-box"}, ProbeURL: r.ProbeURL,
		CIDRs: []string{}, SourceRefs: []string{}, Probes: []catalog.Probe{},
		Provenance: &catalog.Provenance{Provider: "model", EntryID: "telegram", URL: "https://telegram.org/", SHA256: strings.Repeat("c", 64)},
	}
	if namedProbe {
		r.ProbeService.Probes = []catalog.Probe{{ID: "web", Label: "Web", URL: r.ProbeURL, Required: true,
			Expect: catalog.ProbeExpectation{StatusCodes: []int{200}, RedirectPolicy: "none", ContentTypes: []string{"text/html"},
				RedirectHosts: []string{}, JSONFields: []string{}, BodyContains: []string{}},
		}}
	}
	plan, err := BuildAt(Input{Revision: 1, NetworkProfileID: f.plan.NetworkProfileID, Routes: f.plan.Routes}, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if plan.Routes[0].Domains == nil || plan.Routes[0].SourceRefs == nil || plan.Routes[0].Ingress == nil {
		t.Fatal("fixture did not exercise compiled empty slices")
	}
	f.plan = plan
	root := privateScopedXrayFixtureDir(t)
	for _, step := range []func(context.Context, Plan, string) error{f.a.Snapshot, f.a.Stage} {
		if err := step(context.Background(), f.plan, root); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(f.a.runtimeRoot(), 0o700); err != nil {
		t.Fatal(err)
	}
	for source, destination := range map[string]string{
		"nodes.staged.json": f.a.nodeManifestPath(), "engine.staged.json": f.a.engineConfigPath(), "sidecar.staged.json": f.a.sidecarConfigPath(),
	} {
		data, err := os.ReadFile(filepath.Join(root, source))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(destination, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return f, root
}

func TestCompiledScopedNodeManifestRoundTripKeepsOptionalEmptySlices(t *testing.T) {
	for _, namedProbe := range []bool{false, true} {
		t.Run(map[bool]string{false: "default-web-predicate", true: "named-predicate"}[namedProbe], func(t *testing.T) {
			f, _ := compiledScopedManifestFixture(t, namedProbe)
			before, _ := json.Marshal(f.plan)
			manifest, err := f.a.readNodeManifest(f.a.nodeManifestPath())
			if err != nil || manifest.Routes[0].Domains != nil || manifest.Routes[0].SourceRefs != nil || manifest.Routes[0].Ingress != nil {
				t.Fatal("fixture did not actually serialize/omit/read empty slices", manifest, err)
			}
			if !namedProbe && manifest.Routes[0].ProbeService.Probes != nil {
				t.Fatal("optional catalog probes did not round-trip to nil")
			}
			if _, err := f.a.checkScopedNodeState(context.Background(), f.plan); err != nil {
				t.Fatal("equal compiled route refused after actual manifest read", err)
			}
			after, _ := json.Marshal(f.plan)
			if !reflect.DeepEqual(before, after) || f.plan.Routes[0].Domains == nil || f.plan.Routes[0].SourceRefs == nil {
				t.Fatal("comparison mutated the original compiled plan")
			}
		})
	}
}

func TestScopedNodeManifestRoundTripStillRefusesSemanticDrift(t *testing.T) {
	f, _ := compiledScopedManifestFixture(t, true)
	if _, err := f.a.checkScopedNodeState(context.Background(), f.plan); err != nil {
		t.Fatal("unchanged compiled baseline refused", err)
	}
	for name, change := range map[string]func(*Plan){
		"catalog body marker": func(p *Plan) { p.Routes[0].ProbeService.Probes[0].Expect.BodyContains = []string{"changed"} },
		"catalog status":      func(p *Plan) { p.Routes[0].ProbeService.Probes[0].Expect.StatusCodes = []int{204} },
		"catalog provenance":  func(p *Plan) { p.Routes[0].ProbeService.Provenance.SHA256 = strings.Repeat("d", 64) },
		"catalog strategy":    func(p *Plan) { p.Routes[0].ProbeService.Strategy = []string{"sing-box"} },
		"catalog order":       func(p *Plan) { p.Routes[0].ProbeService.Strategy = []string{"sing-box", "xray"} },
		"transport reference": func(p *Plan) { p.Routes[0].WireGuardProfileRevision = strings.Repeat("f", 64) },
		"source reference":    func(p *Plan) { p.Routes[0].SourceRefs = []string{"device-current"} },
		"source":              func(p *Plan) { p.Routes[0].Sources = []string{"192.168.1.26/32"} },
		"generation":          func(p *Plan) { p.Routes[0].NetworkPolicyGeneration = strings.Repeat("a", 64) },
		"role":                func(p *Plan) { p.Routes[0].NetworkPolicyRole = "override" },
		"ingress":             func(p *Plan) { p.Routes[0].Ingress = []string{"br1"} },
		"node": func(p *Plan) {
			route := p.Routes[0].Resolved
			last := "a"
			if strings.HasSuffix(route, last) {
				last = "b"
			}
			p.Routes[0].Resolved = route[:len(route)-1] + last
		},
		"profile": func(p *Plan) { p.NetworkProfileID = "wan-222222222222" },
	} {
		t.Run(name, func(t *testing.T) {
			p := f.plan
			p.Routes = cloneNetworkPolicyRoutes(p.Routes)
			change(&p)
			if _, err := f.a.checkScopedNodeState(context.Background(), p); !errors.Is(err, ErrNodeEndpointChanged) {
				t.Fatal("actual semantic drift was accepted", err)
			}
		})
	}
}

func TestScopedNodeManifestCanonicalComparisonPreservesRequiredCatalogSlices(t *testing.T) {
	left := []Route{{ProbeService: &catalog.Service{Domains: nil, Strategy: []string{"xray"}}}}
	right := []Route{{ProbeService: &catalog.Service{Domains: []string{}, Strategy: []string{"xray"}}}}
	if reflect.DeepEqual(canonicalScopedNodeRoutes(left), canonicalScopedNodeRoutes(right)) {
		t.Fatal("required catalog domains null/empty representations were discarded")
	}
	left[0].ProbeService.Domains = []string{"telegram.org"}
	right[0].ProbeService.Domains = []string{"telegram.org"}
	left[0].ProbeService.Strategy, right[0].ProbeService.Strategy = nil, []string{}
	if reflect.DeepEqual(canonicalScopedNodeRoutes(left), canonicalScopedNodeRoutes(right)) {
		t.Fatal("required catalog strategy null/empty representations were discarded")
	}
}
