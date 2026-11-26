package app

import (
	"slices"
	"strings"
	"testing"

	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/dataplane"
	routecatalog "github.com/ArtixSx/razvilka/internal/routes"
)

func TestNetworkPolicyCannotFallThroughLegacyExecutor(t *testing.T) {
	for _, kind := range []string{"desired", "applied"} {
		cfg := config.Default()
		if kind == "applied" {
			cfg.AppliedNetworkPolicy = &config.NetworkPolicy{Schema: 1}
		} else {
			cfg.NetworkPolicy = &config.NetworkPolicy{Schema: 1}
		}
		for _, scope := range []changeScope{changeScopeAll, changeScopeServices, changeScopeDevices, changeScopeEngine} {
			// No detector, manager or catalog is available: refusal must precede reads
			// and must not silently drop a preserved policy during partial Apply.
			_, err := (&App{}).buildDataplanePlanForScope(cfg, nil, scope, "nfqws2")
			if err == nil || !strings.Contains(err.Error(), "NETWORK_POLICY_EXECUTOR_REQUIRED") {
				t.Fatalf("kind=%v scope=%v err=%v", kind, scope, err)
			}
		}
	}
}

// An earlier release kept an emptied "sites without bypass" document. It has
// no negative to honour, so it must not close legacy Apply for good.
func TestEmptyInactiveExclusionsDoNotCloseLegacyExecutor(t *testing.T) {
	cfg := config.Default()
	cfg.SafeMode = false
	cfg.Services["telegram"] = config.ServiceState{Enabled: true, Route: "nfqws2"}
	a := &App{Catalog: catalog.Catalog{Services: []catalog.Service{{ID: "telegram", Name: "Telegram", Domains: []string{"telegram.org"}}}}}
	options := []routecatalog.Option{{ID: "nfqws2", Installed: true, Selectable: true}}
	for _, doc := range []*config.ResourceExclusions{
		{Schema: 1, Revision: 3, Manual: []config.ResourceMatch{}},
		{Schema: 1, Revision: 3},
	} {
		cfg.InactiveResourceExclusions = doc
		if _, err := a.buildDataplanePlanForScope(cfg, options, changeScopeServices, ""); err != nil && strings.Contains(err.Error(), "NETWORK_POLICY_EXECUTOR_REQUIRED") {
			t.Fatalf("empty inactive document closed legacy Apply: %v", err)
		}
	}
}

// Saved "sites without bypass" reach the whole-network plan: names and
// addresses for NFQWS2. An excluded service keeps its route, so applied state
// and the project switch stay consistent, and its catalog names are excluded.
func TestInactiveExclusionsReachLegacyPlan(t *testing.T) {
	cfg := config.Default()
	cfg.SafeMode = false
	cfg.Services["telegram"] = config.ServiceState{Enabled: true, Route: "nfqws2"}
	cfg.Services["video"] = config.ServiceState{Enabled: true, Route: "nfqws2"}
	a := &App{Catalog: catalog.Catalog{Services: []catalog.Service{
		{ID: "telegram", Name: "Telegram", Domains: []string{"telegram.org"}},
		{ID: "video", Name: "Видео", Domains: []string{"video.example"}, CIDRs: []string{"192.0.2.0/24"}},
	}}}
	options := []routecatalog.Option{{ID: "nfqws2", Installed: true, Selectable: true}}
	cfg.InactiveResourceExclusions = &config.ResourceExclusions{Schema: 1, Revision: 3, Manual: []config.ResourceMatch{
		{Kind: "suffix", Value: "example.com"}, {Kind: "exact", Value: "bank.example.org"},
		{Kind: "ip", Value: "198.51.100.7"}, {Kind: "cidr", Value: "203.0.113.0/24"}, {Kind: "service", Value: "video"},
	}}
	for _, scope := range []changeScope{changeScopeAll, changeScopeServices} {
		plan, err := a.buildDataplanePlanForScope(cfg, options, scope, "")
		if err != nil || plan.SiteExclusions == nil {
			t.Fatalf("scope=%v: exclusions did not reach the plan: %v %+v", scope, err, plan.SiteExclusions)
		}
		got := plan.SiteExclusions
		if !slices.Equal(got.Domains, []string{"bank.example.org", "example.com"}) || !slices.Equal(got.CIDRs, []string{"198.51.100.7", "203.0.113.0/24"}) ||
			!slices.Equal(got.Services, []string{"video"}) || !slices.Equal(got.ServiceDomains, []string{"video.example"}) || !slices.Equal(got.ServiceCIDRs, []string{"192.0.2.0/24"}) {
			t.Fatalf("scope=%v: wrong exclusions %+v", scope, got)
		}
		if len(plan.Routes) != 2 {
			t.Fatalf("scope=%v: an excluded service lost its route: %+v", scope, plan.Routes)
		}
		if !dataplane.PlanHonoursLegacyExclusions(cfg, plan) {
			t.Fatalf("scope=%v: plan does not honour its own exclusions", scope)
		}
	}
	// A plan from before the exclusions were saved must not be replayed.
	cfg.InactiveResourceExclusions.Manual = cfg.InactiveResourceExclusions.Manual[:4]
	stale, err := a.buildDataplanePlanForScope(cfg, options, changeScopeAll, "")
	if err != nil {
		t.Fatal(err)
	}
	cfg.InactiveResourceExclusions.Manual = append(cfg.InactiveResourceExclusions.Manual, config.ResourceMatch{Kind: "service", Value: "telegram"})
	if dataplane.PlanHonoursLegacyExclusions(cfg, stale) {
		t.Fatal("plan with a newly excluded service was accepted for replay")
	}
	cfg.InactiveResourceExclusions.Manual = []config.ResourceMatch{{Kind: "suffix", Value: "example.net"}}
	if dataplane.PlanHonoursLegacyExclusions(cfg, stale) {
		t.Fatal("plan with other site exclusions was accepted for replay")
	}
}

// An excluded service assigned to a VPN or proxy is refused with its own
// reason: only NFQWS2 can leave an enabled service's traffic unprocessed.
func TestExcludedServiceThroughProxyIsBlocked(t *testing.T) {
	cfg := config.Default()
	cfg.SafeMode = false
	cfg.Services["tg-ip"] = config.ServiceState{Enabled: true, Route: "sing-box"}
	a := &App{Catalog: catalog.Catalog{Services: []catalog.Service{{ID: "tg-ip", Name: "Telegram IP", CIDRs: []string{"149.154.160.0/20"}}}}}
	options := []routecatalog.Option{{ID: "sing-box", Installed: true, Selectable: true}}
	cfg.InactiveResourceExclusions = &config.ResourceExclusions{Schema: 1, Revision: 1, Manual: []config.ResourceMatch{{Kind: "service", Value: "tg-ip"}}}
	plan, err := a.buildDataplanePlanForScope(cfg, options, changeScopeAll, "")
	if err != nil {
		t.Fatal(err)
	}
	codes := []string{}
	for _, blocker := range plan.Blockers {
		codes = append(codes, blocker.Code)
	}
	if plan.Ready || !slices.Contains(codes, "SITE_EXCLUSION_SERVICE_ROUTED") || slices.Contains(codes, "SITE_EXCLUSION_CONFLICT") {
		t.Fatalf("excluded proxy service was not refused with its own reason: %v", codes)
	}
}

// A saved whole-network list is pending only while the committed plan does
// not carry it and it would change what runs; a stopped project and the
// home-network mode keep their own state.
func TestSiteExclusionsPendingUntilCommitted(t *testing.T) {
	manager := dataplane.New(t.TempDir())
	a := &App{Dataplane: manager}
	cfg := config.Default()
	if a.siteExclusionsPending(cfg) {
		t.Fatal("an absent list is pending")
	}
	cfg.InactiveResourceExclusions = &config.ResourceExclusions{Schema: 1, Revision: 1, Manual: []config.ResourceMatch{{Kind: "suffix", Value: "example.com"}}}
	if a.siteExclusionsPending(cfg) {
		t.Fatal("a list with nothing to change is pending before any route")
	}
	plan := dataplane.Plan{SchemaVersion: dataplane.SchemaVersion, PlanID: "dp-nfq", Digest: "nfq", State: "committed", Ready: true, Routes: []dataplane.Route{{ServiceID: "youtube", Resolved: "nfqws2", Domains: []string{"youtube.com"}}}}
	if err := manager.Record(plan); err != nil {
		t.Fatal(err)
	}
	if !a.siteExclusionsPending(cfg) {
		t.Fatal("an unapplied list over an NFQWS2 route is not pending")
	}
	stopped := cfg
	stopped.ServiceControl.Stopped = true
	if a.siteExclusionsPending(stopped) {
		t.Fatal("a stopped project reports the list as pending")
	}
	listMode := config.Default()
	listMode.NetworkPolicy = &config.NetworkPolicy{Schema: 1}
	if a.siteExclusionsPending(listMode) {
		t.Fatal("the home-network mode reports a whole-network list")
	}
	plan.SiteExclusions = &dataplane.SiteExclusions{Domains: []string{"example.com"}}
	if err := manager.Record(plan); err != nil {
		t.Fatal(err)
	}
	if a.siteExclusionsPending(cfg) {
		t.Fatal("an applied list is still pending")
	}
	// Address routes only: a list that changes nothing there waits quietly.
	proxy := dataplane.Plan{SchemaVersion: dataplane.SchemaVersion, PlanID: "dp-proxy", Digest: "proxy", State: "committed", Ready: true, Routes: []dataplane.Route{{ServiceID: "tg", Resolved: "sing-box", CIDRs: []string{"149.154.160.0/20"}}}}
	if err := manager.Record(proxy); err != nil {
		t.Fatal(err)
	}
	if a.siteExclusionsPending(cfg) {
		t.Fatal("a domain list over an address route is pending")
	}
	cfg.InactiveResourceExclusions.Manual = append(cfg.InactiveResourceExclusions.Manual, config.ResourceMatch{Kind: "ip", Value: "149.154.167.99"})
	if !a.siteExclusionsPending(cfg) {
		t.Fatal("an excluded address inside a proxy route is not pending")
	}
}
