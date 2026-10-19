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
// addresses for NFQWS2, and an excluded service gets no route at all.
func TestInactiveExclusionsReachLegacyPlan(t *testing.T) {
	cfg := config.Default()
	cfg.SafeMode = false
	cfg.Services["telegram"] = config.ServiceState{Enabled: true, Route: "nfqws2"}
	cfg.Services["video"] = config.ServiceState{Enabled: true, Route: "nfqws2"}
	a := &App{Catalog: catalog.Catalog{Services: []catalog.Service{
		{ID: "telegram", Name: "Telegram", Domains: []string{"telegram.org"}},
		{ID: "video", Name: "Видео", Domains: []string{"video.example"}},
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
		if !slices.Equal(plan.SiteExclusions.Domains, []string{"bank.example.org", "example.com"}) || !slices.Equal(plan.SiteExclusions.CIDRs, []string{"198.51.100.7", "203.0.113.0/24"}) {
			t.Fatalf("scope=%v: wrong exclusions %+v", scope, plan.SiteExclusions)
		}
		if len(plan.Routes) != 1 || plan.Routes[0].ServiceID != "telegram" {
			t.Fatalf("scope=%v: excluded service kept a route: %+v", scope, plan.Routes)
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
