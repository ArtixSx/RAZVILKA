package app

import (
	"context"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/autonomy"
	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/nodestore"
	routecatalog "github.com/ArtixSx/razvilka/internal/routes"
)

func starterService(t *testing.T, id string) catalog.Service {
	t.Helper()
	for _, s := range catalog.NFQWS2Starter().Services {
		if s.ID == id {
			return s
		}
	}
	t.Fatalf("starter service %s missing", id)
	return catalog.Service{}
}

// The autopilot first assigns an exact node to Discord (an NFQWS2-list
// service), as it did on the owner's router, with real stores, plan compiler
// and transaction manager; only adapters and the node checker are fakes.
func nfqws2StandardFixture(t *testing.T, service catalog.Service) (*App, string, *nodeApplyAdapter) {
	return nfqws2StandardScopedFixture(t, service, nil)
}

func nfqws2StandardScopedFixture(t *testing.T, service catalog.Service, devices []string) (*App, string, *nodeApplyAdapter) {
	t.Helper()
	a, _, adapter := nodeApplyFixture(t)
	a.Catalog.Services = []catalog.Service{service}
	snapshot, err := a.Nodes.Import(context.Background(), nodestore.Source{ID: "feed", Kind: "manual"}, "vless://123e4567-e89b-12d3-a456-426614174002@feed.example:443?security=tls", time.Now(), time.Hour, false)
	if err != nil {
		t.Fatal(err)
	}
	node := ""
	for _, n := range snapshot.Nodes {
		for _, o := range n.Origins {
			if o.SourceID == "feed" {
				node = n.ID
			}
		}
	}
	// Both fakes share one call log and can retire their routes, like the
	// real sing-box and NFQWS2 adapters.
	a.Dataplane.Adapters["sing-box"] = &serviceRuntimeAdapter{nodeApplyAdapter: adapter, name: "sing-box"}
	if err = a.Dataplane.Register(&serviceRuntimeAdapter{nodeApplyAdapter: adapter, name: "nfqws2"}); err != nil {
		t.Fatal(err)
	}
	a.DataplaneHost = func() dataplane.HostState {
		return dataplane.HostState{IPCommand: true, TUN: true, SingBox: true, IPTables: true, IP6Tables: true, NFQueueTarget: true, NFQWS2Config: true, NFQWS2Init: true, OffloadState: "disabled"}
	}
	a.nodeReviews.options = func() []routecatalog.Option {
		return []routecatalog.Option{{ID: "direct", Installed: true, Configured: true, Selectable: true, Ready: true},
			{ID: "nfqws2", Installed: true, Configured: true, Running: true, Selectable: true, Ready: true},
			{ID: "sing-box", Installed: true, Configured: true, Selectable: true},
			{ID: "sing-box:" + node, Installed: true, Configured: true, Selectable: true, Services: []string{service.ID}}}
	}
	a.NodeChecker = jobNodeChecker(func(_ context.Context, r dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
		return autofallbackResult(r, true), nil
	})
	p := autonomy.Default()
	p.SetupComplete, p.Enabled, p.InheritNewServices = true, true, true
	p.AllLAN, p.DefaultSources = len(devices) == 0, devices
	p.SourceIDs = []string{"feed"}
	p.PreferredRoutes = nil
	p.ReserveTarget = 1
	p.Application.Mode, p.Components.Mode = "off", "off"
	w := httptest.NewRecorder()
	a.autonomyAPI(w, autonomyRequest("PUT", "/api/v1/autonomy", map[string]any{"expected_revision": 0, "policy": p, "confirm": "SAVE_AUTONOMY", "release_safe_mode": true}))
	if w.Code != 200 {
		t.Fatalf("setup %d %s", w.Code, w.Body.String())
	}
	if err = a.inheritAutonomyService(context.Background(), service.ID); err != nil {
		t.Fatal(err)
	}
	a.autonomyRound(context.Background(), time.Now())
	if route := selectedRoute(a.Store.Get().AppliedServices[service.ID]); route != "sing-box:"+node {
		t.Fatalf("fixture node not applied: %q %+v", route, standardRuntime(a, service.ID))
	}
	adapter.calls = nil
	return a, node, adapter
}

func standardRuntime(a *App, id string) autonomy.Runtime {
	a.autonomy.mu.Lock()
	defer a.autonomy.mu.Unlock()
	return a.autonomy.doc.Runtime[id].Clone()
}

func standardDue(a *App, id string) {
	a.autonomy.mu.Lock()
	defer a.autonomy.mu.Unlock()
	r := a.autonomy.doc.Runtime[id]
	r.NextCheck = time.Time{}
	a.autonomy.doc.Runtime[id] = r
	_ = a.persistAutonomyLocked(context.Background())
}

func standardExpected(a *App, id string) string {
	a.autonomy.mu.Lock()
	defer a.autonomy.mu.Unlock()
	return a.autonomy.doc.Services[id].ExpectedRoute
}

func TestAutopilotReturnsNFQWS2ServiceFromUnavailableNode(t *testing.T) {
	a, node, adapter := nfqws2StandardFixture(t, starterService(t, "discord"))
	if _, err := a.Nodes.SetDisabled(context.Background(), node, true, time.Now()); err != nil {
		t.Fatal(err)
	}
	standardDue(a, "discord")
	a.autonomyRound(context.Background(), time.Now())
	cfg := a.Store.Get()
	r := standardRuntime(a, "discord")
	if r.State != "applied" || selectedRoute(cfg.AppliedServices["discord"]) != "nfqws2" || selectedRoute(cfg.Services["discord"]) != "nfqws2" || !strings.Contains(r.Message, "NFQWS2") {
		t.Fatalf("not returned to NFQWS2: %+v applied=%+v", r, cfg.AppliedServices["discord"])
	}
	if len(cfg.AppliedServices["discord"].Sources) != 0 || standardExpected(a, "discord") != "nfqws2" {
		t.Fatalf("scope or expectation lost: %+v %q", cfg.AppliedServices["discord"], standardExpected(a, "discord"))
	}
	if !slices.Contains(adapter.calls, "commit") {
		t.Fatalf("transaction bypassed: %v", adapter.calls)
	}
	// The standard route is kept: a returning node is not selected again.
	if _, err := a.Nodes.SetDisabled(context.Background(), node, false, time.Now()); err != nil {
		t.Fatal(err)
	}
	adapter.calls = nil
	standardDue(a, "discord")
	a.autonomyRound(context.Background(), time.Now())
	if selectedRoute(a.Store.Get().AppliedServices["discord"]) != "nfqws2" || slices.Contains(adapter.calls, "commit") {
		t.Fatalf("standard route replaced: %+v %v", standardRuntime(a, "discord"), adapter.calls)
	}
}

func TestAutopilotKeepsWorkingNodeOfNFQWS2Service(t *testing.T) {
	a, node, _ := nfqws2StandardFixture(t, starterService(t, "discord"))
	standardDue(a, "discord")
	a.autonomyRound(context.Background(), time.Now())
	if route := selectedRoute(a.Store.Get().AppliedServices["discord"]); route != "sing-box:"+node {
		t.Fatalf("working node replaced: %q %+v", route, standardRuntime(a, "discord"))
	}
}

// Only the reviewed NFQWS2 list has NFQWS2 as its standard route.
func TestAutopilotDoesNotMoveOtherServiceToNFQWS2(t *testing.T) {
	a, node, _ := nfqws2StandardFixture(t, catalog.Service{ID: "my-site", Name: "My site", Domains: []string{"example.org"}, ProbeURL: "https://example.org/"})
	if _, err := a.Nodes.SetDisabled(context.Background(), node, true, time.Now()); err != nil {
		t.Fatal(err)
	}
	standardDue(a, "my-site")
	a.autonomyRound(context.Background(), time.Now())
	if route := selectedRoute(a.Store.Get().AppliedServices["my-site"]); route != "sing-box:"+node {
		t.Fatalf("service outside the NFQWS2 list moved: %q", route)
	}
}

// Regression for the owner's router: Discord's draft was returned to NFQWS2
// while the unavailable node stayed applied, and the autopilot paused on a
// "manual change" while every other service waited for Discord.
func TestAutopilotAppliesOwnersReturnToNFQWS2(t *testing.T) {
	a, node, adapter := nfqws2StandardFixture(t, starterService(t, "discord"))
	if _, err := a.Nodes.SetDisabled(context.Background(), node, true, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := a.Store.UpdateService("discord", config.ServiceState{Enabled: true, Mode: "nfqws2", Route: "nfqws2"}); err != nil {
		t.Fatal(err)
	}
	standardDue(a, "discord")
	a.autonomyRound(context.Background(), time.Now())
	cfg := a.Store.Get()
	r := standardRuntime(a, "discord")
	if r.State != "applied" || selectedRoute(cfg.AppliedServices["discord"]) != "nfqws2" || !strings.Contains(r.Message, "Ваш возврат") || !slices.Contains(adapter.calls, "commit") {
		t.Fatalf("owner's return not applied: %+v applied=%+v calls=%v", r, cfg.AppliedServices["discord"], adapter.calls)
	}
}

func TestAutopilotStillPausesOnOtherManualChanges(t *testing.T) {
	for name, draft := range map[string]config.ServiceState{
		"other route":   {Enabled: true, Route: "direct"},
		"other devices": {Enabled: true, Route: "nfqws2", Sources: []string{"192.168.1.51/32"}},
		"disabled":      {Enabled: false, Route: "nfqws2"},
	} {
		t.Run(name, func(t *testing.T) {
			a, node, adapter := nfqws2StandardFixture(t, starterService(t, "discord"))
			if err := a.Store.UpdateService("discord", draft); err != nil {
				t.Fatal(err)
			}
			standardDue(a, "discord")
			a.autonomyRound(context.Background(), time.Now())
			if r := standardRuntime(a, "discord"); r.State != "manual-change" || len(adapter.calls) != 0 || selectedRoute(a.Store.Get().AppliedServices["discord"]) != "sing-box:"+node {
				t.Fatalf("manual change applied: %+v calls=%v", r, adapter.calls)
			}
		})
	}
}

// NFQWS2 cannot be limited to selected devices: a device-scoped autopilot keeps
// its previous behaviour and never widens the scope to the whole LAN.
func TestAutopilotDeviceScopeDoesNotReturnToNFQWS2(t *testing.T) {
	a, node, adapter := nfqws2StandardScopedFixture(t, starterService(t, "discord"), []string{"192.168.1.50/32"})
	if _, err := a.Nodes.SetDisabled(context.Background(), node, true, time.Now()); err != nil {
		t.Fatal(err)
	}
	standardDue(a, "discord")
	a.autonomyRound(context.Background(), time.Now())
	if route := selectedRoute(a.Store.Get().AppliedServices["discord"]); route != "sing-box:"+node || slices.Contains(adapter.calls, "commit") {
		t.Fatalf("device-scoped service widened to NFQWS2: %q %+v", route, standardRuntime(a, "discord"))
	}
}
