package app

import (
	"context"
	"reflect"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/routekind"
	routecatalog "github.com/ArtixSx/razvilka/internal/routes"
	"github.com/ArtixSx/razvilka/internal/testlab"
)

type domainAutopilotRecorder struct {
	mu         sync.Mutex
	probed     []string
	nodeChecks int
}

func (r *domainAutopilotRecorder) routes() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.probed)
}

// Every preferred executor is installed and ready; the prober never confirms
// a route, so the only observable choice is which routes were even tried.
func domainAutopilotFixture(t *testing.T, service catalog.Service, nfqReady bool) (*App, *nodeApplyAdapter, *domainAutopilotRecorder) {
	t.Helper()
	a, _, adapter := autonomousIntegrationFixture(t)
	rec := &domainAutopilotRecorder{}
	a.Catalog.Services = append(a.Catalog.Services, service)
	if err := a.Store.UpdateService(service.ID, config.ServiceState{Enabled: true, Route: "auto"}); err != nil {
		t.Fatal(err)
	}
	if err := a.inheritAutonomyService(context.Background(), service.ID); err != nil {
		t.Fatal(err)
	}
	a.autonomy.mu.Lock()
	p := a.autonomy.doc.Policy
	p.PreferredRoutes = routekind.PreferredIDs()
	a.autonomy.doc.Policy = p
	other := a.autonomy.doc.Runtime["my-independent-site"]
	other.NextCheck = time.Now().Add(time.Hour)
	a.autonomy.doc.Runtime["my-independent-site"] = other
	if err := a.persistAutonomyLocked(context.Background()); err != nil {
		t.Fatal(err)
	}
	a.autonomy.mu.Unlock()
	options := a.nodeReviews.options
	a.nodeReviews.options = func() []routecatalog.Option {
		out := options()
		for _, id := range routekind.PreferredIDs() {
			if id != "nfqws2" || nfqReady {
				out = append(out, routecatalog.Option{ID: id, Installed: true, Configured: true, Selectable: true, Running: true, Ready: true})
			}
		}
		return out
	}
	a.TestLab = testlab.NewRunner()
	a.RouteProber = autonomyResourceRouteProber(func(_ context.Context, s catalog.Service, route string) testlab.Result {
		rec.mu.Lock()
		rec.probed = append(rec.probed, route)
		rec.mu.Unlock()
		return testlab.Result{ServiceID: s.ID, ServiceName: s.Name, ProbeURL: s.ProbeURL, Route: route, Status: "error", CheckedAt: time.Now().UTC().Format(time.RFC3339)}
	})
	a.NodeChecker = jobNodeChecker(func(_ context.Context, r dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
		rec.mu.Lock()
		rec.nodeChecks++
		rec.mu.Unlock()
		return autofallbackResult(r, false), nil
	})
	return a, adapter, rec
}

func domainAutopilotState(a *App, id string) (string, string) {
	a.autonomy.mu.Lock()
	defer a.autonomy.mu.Unlock()
	r := a.autonomy.doc.Runtime[id]
	return r.State, r.Message
}

func domainAutopilotDue(a *App, id string) {
	a.autonomy.mu.Lock()
	defer a.autonomy.mu.Unlock()
	r := a.autonomy.doc.Runtime[id]
	r.NextCheck = time.Time{}
	a.autonomy.doc.Runtime[id] = r
	_ = a.persistAutonomyLocked(context.Background())
}

// The 2026-10-18 incident class must not come back as an automatic fallback:
// a domain service is never probed, reserved or applied through a VPN/proxy
// route, and it ends in one typed state instead of an endless apply refusal.
func TestAutopilotDomainServiceSkipsIPPolicyRoutes(t *testing.T) {
	for _, nfqReady := range []bool{false, true} {
		service := catalog.Service{ID: "domain-site", Name: "Domain site", Domains: []string{"site.example"}, ProbeURL: "https://site.example/"}
		a, adapter, rec := domainAutopilotFixture(t, service, nfqReady)
		before := a.Store.Get()
		committed, _, _ := a.Dataplane.Committed()
		for round := 0; round < 2; round++ {
			domainAutopilotDue(a, service.ID)
			a.autonomyRound(context.Background(), time.Now())
		}
		want := []string{}
		if nfqReady {
			want = []string{"nfqws2", "nfqws2"}
		}
		if got := rec.routes(); !slices.Equal(got, want) {
			t.Fatalf("nfq=%v: probed %v", nfqReady, got)
		}
		state, message := domainAutopilotState(a, service.ID)
		if state != autonomyStateDomainRouteUnavailable || message == "" || rec.nodeChecks != 0 || len(adapter.calls) != 0 {
			t.Fatalf("nfq=%v: %s %q checks=%d calls=%v", nfqReady, state, message, rec.nodeChecks, adapter.calls)
		}
		current, _, _ := a.Dataplane.Committed()
		if !reflect.DeepEqual(before, a.Store.Get()) || !reflect.DeepEqual(committed, current) {
			t.Fatal("ineligible route changed configuration or runtime")
		}
		a.autonomy.mu.Lock()
		reserves := a.autonomy.doc.Runtime[service.ID].Reserves
		a.autonomy.mu.Unlock()
		if len(reserves) != 0 {
			t.Fatal("node reserves prepared for a domain service", reserves)
		}
	}
}

// CIDR-only services keep every executor the owner allowed.
func TestAutopilotCIDRServiceStillTriesEveryPreferredRoute(t *testing.T) {
	service := catalog.Service{ID: "cidr-site", Name: "CIDR site", CIDRs: []string{"198.51.100.0/24"}, ProbeURL: "https://cidr.example/"}
	a, _, rec := domainAutopilotFixture(t, service, true)
	domainAutopilotDue(a, service.ID)
	a.autonomyRound(context.Background(), time.Now())
	if got := rec.routes(); !slices.Equal(got, routekind.PreferredIDs()) {
		t.Fatalf("CIDR service lost eligible routes: %v", got)
	}
	if state, _ := domainAutopilotState(a, service.ID); state == autonomyStateDomainRouteUnavailable {
		t.Fatal("CIDR service reported as a domain service")
	}
}

func TestAutonomyRouteEligibilityMatchesPlanBlocker(t *testing.T) {
	domain := catalog.Service{ID: "d", Domains: []string{"site.example"}}
	mixed := catalog.Service{ID: "m", Domains: []string{"site.example"}, CIDRs: []string{"198.51.100.0/24"}}
	cidr := catalog.Service{ID: "c", CIDRs: []string{"198.51.100.0/24"}}
	for _, route := range append(routekind.PreferredIDs(), "wireguard:home", "sing-box:node-x", "xray:node-x") {
		if !routeEligibleForService(cidr, route) {
			t.Fatalf("CIDR service lost %s", route)
		}
		for _, service := range []catalog.Service{domain, mixed} {
			if routeEligibleForService(service, route) != (route == "nfqws2") || routeEligibleForService(service, route) != dataplane.DomainFlowAuthority(route) {
				t.Fatalf("%s: %s eligibility disagrees with the plan", service.ID, route)
			}
		}
	}
}

// A sing-box group route that an older release committed with domains keeps
// its runtime until the owner changes it, but the fallback worker neither
// checks reserves for it nor builds a switch that the plan would refuse.
func TestNodeAutofallbackDomainRouteIsNotCheckedOrSwitched(t *testing.T) {
	a, _, _, adapter, previous := nodeAutofallbackFixture(t, 1)
	previous.Routes[0].Domains = []string{"telegram.org"}
	if err := a.Dataplane.Record(previous); err != nil {
		t.Fatal(err)
	}
	checks := 0
	a.NodeChecker = jobNodeChecker(func(_ context.Context, r dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
		checks++
		return autofallbackResult(r, false), nil
	})
	now := time.Now()
	for round := 0; round < 3; round++ {
		a.nodeAutofallbackRound(context.Background(), now.Add(time.Duration(round)*time.Minute))
	}
	status := fallbackEntry(t, a)
	current, _, err := a.Dataplane.Committed()
	if err != nil || status.State != autonomyStateDomainRouteUnavailable || status.Healthy || checks != 0 || len(adapter.calls) != 0 || !reflect.DeepEqual(current.Routes, previous.Routes) {
		t.Fatalf("domain route entered node fallback: %+v checks=%d calls=%v", status, checks, adapter.calls)
	}
}

// AUTO is the other preference list. Resolving a domain service to a refused
// route would put DOMAIN_FLOW_AUTHORITY_REQUIRED into every later Apply,
// including the autopilot's own transactions for unrelated services.
func TestAutoRouteNeverResolvesDomainServiceToIPPolicy(t *testing.T) {
	options := []routecatalog.Option{{ID: "direct", Selectable: true, Ready: true}}
	for _, id := range routekind.PreferredIDs() {
		if id != "nfqws2" {
			options = append(options, routecatalog.Option{ID: id, Installed: true, Configured: true, Selectable: true, Running: true, Ready: true})
		}
	}
	order := config.Default().EngineOrder
	domain := catalog.Service{ID: "domain-site", Domains: []string{"site.example"}, Strategy: []string{"warp-wg", "amneziawg"}}
	if got := plannedEngineWithOptions(domain, order, options); got != "direct" {
		t.Fatalf("domain service resolved to %q", got)
	}
	cidr := catalog.Service{ID: "cidr-site", CIDRs: []string{"198.51.100.0/24"}, Strategy: domain.Strategy}
	if got := plannedEngineWithOptions(cidr, order, options); got != "warp-wg" {
		t.Fatalf("CIDR service lost its strategy: %q", got)
	}
	options = append(options, routecatalog.Option{ID: "nfqws2", Installed: true, Configured: true, Selectable: true, Running: true, Ready: true})
	if got := plannedEngineWithOptions(domain, order, options); got != "nfqws2" {
		t.Fatalf("domain service skipped NFQWS2: %q", got)
	}
}
