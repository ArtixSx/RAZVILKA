package app

import (
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/autonomy"
	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/dataplane"
)

func TestXrayHomeCompilationPreservesNegativePacketScope(t *testing.T) {
	a, b, _ := nfqwsPacketFixture(t)
	cfg := a.Store.Get()
	target := "xray:node-" + strings.Repeat("a", 24)
	state := cfg.Services["listed"]
	state.Route = target
	cfg.Services["listed"] = state
	s := b.snapshot
	svc := catalog.Service{ID: "listed", CIDRs: []string{"9.9.9.9/32"}, ProbeURL: "https://9.9.9.9/"}
	route := dataplane.Route{ServiceID: svc.ID, Selected: target, Resolved: target, ProbeService: &svc, ProbeURL: svc.ProbeURL, CIDRs: slices.Clone(svc.CIDRs)}
	snap := DefaultRouteSnapshot{NodeGeneration: 9, ProfileGeneration: 9, Authority: s.Authority, DNSMode: "baseline", Scope: autonomy.ScopeObservation{BootID: s.Facts.Identity.BootID, NetworkID: s.NetworkID, Revision: s.Facts.Intent.Revision}, Paths: map[string]DefaultRoutePath{"listed": {Selected: target, Resolved: target, ProbeURL: svc.ProbeURL, ProfileDigest: strings.Repeat("1", 64), ProofDigest: strings.Repeat("2", 64)}}}
	c, err := compileXrayHomeTCP(cfg, s, snap, route)
	if err != nil {
		t.Fatal(err)
	}
	g := c.LAN().Ingress[0]
	if g.Membership != "all" || len(g.IncludedMACs) != 0 || !slices.Equal(g.Sources, []string{"192.168.1.0/24"}) || !slices.Contains(g.ExcludedSources, "192.168.1.1/32") || !slices.Contains(g.ExcludedSources, "192.168.1.64/26") || !slices.Contains(g.ExcludedMACs, "02:00:00:00:00:55") || !slices.Contains(g.ExcludedMACs, "02:00:00:00:00:FF") {
		t.Fatalf("wrong Home gate: %+v", g)
	}
	if len(c.rules) != 1 || c.rules[0].Destination.String() != svc.CIDRs[0] || c.rules[0].Protocol != "tcp" || c.rules[0].FirstPort != 443 || c.rules[0].LastPort != 443 {
		t.Fatalf("unexpected rules: %+v", c.rules)
	}
	again := s
	again.Facts.ScopeID = strings.Repeat("7", 32)
	same, err := compileXrayHomeTCP(cfg, again, snap, route)
	if err != nil || same.Digest() != c.Digest() {
		t.Fatal("ephemeral scope polluted review digest", err)
	}
	retired := s
	retired.Facts.ExcludedMACs = nil
	if altered, err := compileXrayHomeTCP(cfg, retired, snap, route); err == nil || altered != nil {
		t.Fatal("dropped negative identity accepted")
	}
	singleton := s
	singleton.Facts = defaultRoutePacketFactsClone(s.Facts)
	singleton.Facts.IPv4Prefixes = []string{"192.168.1.42/32"}
	singleton.Facts.Home.Prefixes = []string{"192.168.1.42/32"}
	if altered, err := compileXrayHomeTCP(cfg, singleton, snap, route); err == nil || altered != nil {
		t.Fatal("Home purpose collapsed to legacy single host")
	}
	stale := snap
	stale.NodeGeneration++
	if altered, err := compileXrayHomeTCP(cfg, s, stale, route); err == nil || altered != nil {
		t.Fatal("borrowed generation accepted")
	}
	for _, tc := range []struct {
		name   string
		mutate func(*dataplane.Route)
	}{
		{"excluded destination", func(r *dataplane.Route) {
			r.CIDRs = []string{"203.0.113.193/32"}
			r.ProbeService.CIDRs = slices.Clone(r.CIDRs)
		}},
		{"whole subnet", func(r *dataplane.Route) {
			r.CIDRs = []string{"203.0.113.0/25"}
			r.ProbeService.CIDRs = slices.Clone(r.CIDRs)
		}},
		{"scoped source", func(r *dataplane.Route) { r.Sources = []string{"192.168.1.40/32"} }},
		{"unrelated URL", func(r *dataplane.Route) {
			r.ProbeService.Probes = []catalog.Probe{{URL: "https://www.example.org/", Required: true}}
		}},
		{"wrong service port", func(r *dataplane.Route) {
			r.ProbeService.Probes = []catalog.Probe{{URL: "https://9.9.9.9:8443/", Required: true}}
		}},
		{"domain in original probe", func(r *dataplane.Route) { r.ProbeService.Domains = []string{"example.test"} }},
		{"another frozen destination", func(r *dataplane.Route) { r.ProbeService.CIDRs = []string{"9.9.9.10/32"} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := defaultRouteCloneRoutes([]dataplane.Route{route})[0]
			tc.mutate(&r)
			if c, err := compileXrayHomeTCP(cfg, s, snap, r); c != nil || err == nil {
				t.Fatal("unsupported scope accepted")
			}
		})
	}
	copy := xrayHomeScopeBinding{base: b}
	copy.self = &copy
	if copy.original() || (xrayRuntimeScope{home: &copy}).original() {
		t.Fatal("modeled NFQ owner promoted to physical Xray")
	}
	if !reflect.DeepEqual(route.CIDRs, svc.CIDRs) {
		t.Fatal("caller service mutated")
	}
}

func TestXrayHomeMaterialRefusalExplainsNativePolicy(t *testing.T) {
	for _, tc := range []struct {
		stage string
		extra error
		want  string
	}{
		{"prepare", nil, "XRAY_HOME_NATIVE_PATH_UNAVAILABLE"},
		{"cleanup", nil, "XRAY_SELECTED_TCP_REVIEW_REFUSED"},
		{"prepare", context.DeadlineExceeded, "XRAY_SELECTED_TCP_REVIEW_REFUSED"},
	} {
		err := managedXrayReviewAt(tc.stage, context.Background(), errors.Join(dataplane.ErrXrayHomeNativePath, tc.extra))
		w := httptest.NewRecorder()
		writeManagedXrayReviewError(w, err, time.Now())
		var body map[string]any
		if json.Unmarshal(w.Body.Bytes(), &body) != nil || w.Code != 409 || body["code"] != tc.want {
			t.Fatal(w.Body.String())
		}
		if tc.want == "XRAY_HOME_NATIVE_PATH_UNAVAILABLE" && (body["capability_refusal"] != true || body["working_routes_changed"] != false || body["live_applied"] != false) {
			t.Fatal(body)
		}
	}
}
