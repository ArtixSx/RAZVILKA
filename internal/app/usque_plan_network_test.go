package app

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/dataplane"
	routecatalog "github.com/ArtixSx/razvilka/internal/routes"
)

type usquePlanContextKey struct{}

func usquePlanFixture(t *testing.T, selected string) (*App, config.Config, []routecatalog.Option) {
	t.Helper()
	a := genericReviewFixture(t)
	a.Catalog.Services[0].Category = "Messaging"
	a.Catalog.Services[0].ProbeURL = "https://telegram.org/"
	a.Catalog.Services[0].Strategy = []string{"usque"}
	// A VPN or proxy route carries only an IP-defined service: domains of a
	// service could share addresses with foreign sites (DOMAIN_FLOW authority).
	a.Catalog.Services[0].Domains = nil
	a.Catalog.Services[0].CIDRs = []string{"149.154.160.0/20"}
	if err := a.Store.UpdateService("telegram", config.ServiceState{Enabled: true, Route: selected, Sources: []string{"192.168.1.40/32"}}); err != nil {
		t.Fatal(err)
	}
	return a, a.Store.Get(), []routecatalog.Option{{ID: "usque", Installed: true, Selectable: true, Ready: true}}
}

func TestOrdinaryUSQUEPlanAndReviewBindFreshOriginalContext(t *testing.T) {
	for _, selected := range []string{"usque", "auto"} {
		for _, preserve := range []bool{false, true} {
			t.Run(selected+map[bool]string{true: "/preserve", false: "/normal"}[preserve], func(t *testing.T) {
				a, cfg, options := usquePlanFixture(t, selected)
				ctx, cancel := context.WithTimeout(context.WithValue(context.Background(), usquePlanContextKey{}, "original"), time.Minute)
				defer cancel()
				profile, calls := "wan-0123456789ab", 0
				a.FreshProfile = func(c context.Context) (string, error) {
					calls++
					if c != ctx || c.Value(usquePlanContextKey{}) != "original" {
						t.Fatal("plan or review lost original context")
					}
					return profile, nil
				}
				url := "/api/v1/plan?scope=services"
				if preserve {
					url += "&engine_drafts=preserve"
				}
				r := httptest.NewRequest(http.MethodGet, url, nil).WithContext(ctx)
				plan, err := a.buildDataplanePlanForRequest(cfg, options, changeScopeServices, "", r)
				if err != nil || plan.NetworkProfileID != profile || len(plan.Routes) != 1 || plan.Routes[0].Resolved != "usque" || plan.RequiresNetworkProof() || calls != 2 {
					t.Fatal("ordinary USQUE plan lacks fresh frozen WAN", err, plan.NetworkProfileID, calls)
				}
				binding, err := a.bindApplyReview(ctx, cfg, plan, changeScopeServices, "")
				if err != nil || binding.nodes {
					t.Fatal("ordinary USQUE review requires node registry", err)
				}
				if err := binding.guard(a, ctx); err != nil {
					t.Fatal(err)
				}
				profile = "wan-222222222222"
				if err := binding.guard(a, ctx); !errors.Is(err, dataplane.ErrNetworkChanged) {
					t.Fatal("review accepted changed WAN", err)
				}
				newPlan, err := a.buildDataplanePlanForRequest(cfg, options, changeScopeServices, "", r)
				if err != nil || newPlan.NetworkProfileID != profile || newPlan.Digest == plan.Digest || !reflect.DeepEqual(cfg, a.Store.Get()) {
					t.Fatal("WAN change did not replace review digest without mutation", err)
				}
			})
		}
	}
}

func TestOrdinaryUSQUEPlanRefusesUnknownChangedAndCancelledNetwork(t *testing.T) {
	for _, scenario := range []string{"unknown", "changed", "cancel-first", "cancel-closing", "cancel-before"} {
		t.Run(scenario, func(t *testing.T) {
			a, cfg, options := usquePlanFixture(t, "usque")
			ctx, cancel := context.WithCancel(context.WithValue(context.Background(), usquePlanContextKey{}, "original"))
			defer cancel()
			calls := 0
			a.FreshProfile = func(c context.Context) (string, error) {
				calls++
				if c != ctx {
					t.Fatal("network read escaped original context")
				}
				if scenario == "cancel-first" || scenario == "cancel-closing" && calls == 2 {
					cancel()
				}
				if scenario == "unknown" {
					return "network-unknown", nil
				}
				if scenario == "changed" && calls == 2 {
					return "wan-222222222222", nil
				}
				return "wan-0123456789ab", nil
			}
			if scenario == "cancel-before" {
				cancel()
			}
			r := httptest.NewRequest(http.MethodGet, "/api/v1/plan", nil).WithContext(ctx)
			plan, err := a.buildDataplanePlanForRequest(cfg, options, changeScopeAll, "", r)
			wanted := dataplane.ErrExactNodeNetworkChanged
			if scenario == "cancel-first" || scenario == "cancel-closing" || scenario == "cancel-before" {
				wanted = context.Canceled
			}
			if !errors.Is(err, wanted) || plan.PlanID != "" || !reflect.DeepEqual(cfg, a.Store.Get()) {
				t.Fatal("invalid WAN authorized a plan", err)
			}
			if scenario == "cancel-before" && calls != 0 {
				t.Fatal("cancelled request read the WAN")
			}
		})
	}
}

func TestOrdinaryDirectPlanDoesNotRequireWANObservation(t *testing.T) {
	a := genericReviewFixture(t)
	a.FreshProfile = func(context.Context) (string, error) {
		t.Fatal("direct plan unexpectedly requires USQUE WAN authority")
		return "", nil
	}
	r := httptest.NewRequest(http.MethodGet, "/api/v1/plan", nil)
	plan, err := a.buildDataplanePlanForRequest(a.Store.Get(), nil, changeScopeAll, "", r)
	if err != nil || plan.NetworkProfileID != "" {
		t.Fatal(err, plan.NetworkProfileID)
	}
}

func TestOrdinaryUSQUEReviewRefusesUnknownAndCancelledNetwork(t *testing.T) {
	for _, scenario := range []string{"unknown", "cancel-nil", "cancel-before"} {
		t.Run(scenario, func(t *testing.T) {
			a, cfg, options := usquePlanFixture(t, "usque")
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			a.FreshProfile = stableNodeProfile
			plan, err := a.buildDataplanePlanForScopeContext(ctx, cfg, options, changeScopeServices, "")
			if err != nil {
				t.Fatal(err)
			}
			binding, err := a.bindApplyReview(ctx, cfg, plan, changeScopeServices, "")
			if err != nil {
				t.Fatal(err)
			}
			calls := 0
			a.FreshProfile = func(c context.Context) (string, error) {
				calls++
				if c != ctx {
					t.Fatal("review escaped original context")
				}
				if scenario == "cancel-nil" {
					cancel()
				}
				if scenario == "unknown" {
					return "network-unknown", nil
				}
				return "wan-0123456789ab", nil
			}
			if scenario == "cancel-before" {
				cancel()
			}
			wanted := dataplane.ErrNetworkChanged
			if scenario != "unknown" {
				wanted = context.Canceled
			}
			if err := binding.guard(a, ctx); !errors.Is(err, wanted) || !reflect.DeepEqual(cfg, a.Store.Get()) {
				t.Fatal("review authorized invalid WAN", err)
			}
			if scenario == "cancel-before" && calls != 0 {
				t.Fatal("cancelled review observed WAN")
			}
		})
	}
}

func TestScopedDNSPlanUsesOriginalContextForWANAndClosingCheck(t *testing.T) {
	a := dnsRuntimeFixture(t)
	ctx, cancel := context.WithTimeout(context.WithValue(context.Background(), usquePlanContextKey{}, "original-dns"), time.Minute)
	defer cancel()
	calls := 0
	a.FreshProfile = func(c context.Context) (string, error) {
		calls++
		if c != ctx {
			t.Fatal("DNS plan escaped original context")
		}
		return "wan-0123456789ab", nil
	}
	plan, err := a.buildDataplanePlanForScopeContext(ctx, a.Store.Get(), nil, changeScopeServices, "")
	if err != nil || plan.DNS == nil || plan.NetworkProfileID != "wan-0123456789ab" || calls != 2 {
		t.Fatal("DNS profile lacks original-context closing check", err, calls)
	}
}
