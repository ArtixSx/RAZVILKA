package app

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/dataplane"
)

// Exercises the ordinary plan/review contract consumed by USQUE canary;
// modeled WAN does not claim native runtime or network acceptance.
func TestOrdinaryUSQUEPlanFreezesCatalogServicePredicate(t *testing.T) {
	for _, selected := range []string{"usque", "auto"} {
		t.Run(selected, func(t *testing.T) {
			a, cfg, options := usquePlanFixture(t, selected)
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			a.FreshProfile = func(context.Context) (string, error) { return "wan-0123456789ab", nil }
			service := &a.Catalog.Services[0]
			service.Probes = []catalog.Probe{{ID: "telegram-web", Label: "Telegram web", URL: service.ProbeURL, Required: true, Expect: catalog.ProbeExpectation{
				StatusCodes: []int{200}, RedirectPolicy: "allowlist", RedirectHosts: []string{"telegram.org"}, ContentTypes: []string{"text/html"}, BodyContains: []string{"Telegram"},
			}}}
			expected := defaultRouteCloneCatalogService(*service)
			plan, err := a.buildDataplanePlanForScopeContext(ctx, cfg, options, changeScopeServices, "")
			if err != nil || len(plan.Routes) != 1 || plan.Routes[0].Resolved != "usque" {
				t.Fatal("ordinary USQUE plan unavailable", err)
			}
			route := plan.Routes[0]
			frozen, err := dataplane.FrozenProbeService(route)
			if err != nil || route.LogicalServiceID != service.ID || !reflect.DeepEqual(frozen, expected) {
				t.Fatal("canary cannot consume exact catalog predicate", err)
			}
			binding, err := a.bindApplyReview(ctx, cfg, plan, changeScopeServices, "")
			if err != nil {
				t.Fatal(err)
			}
			service.Probes[0].Expect.StatusCodes[0] = 403
			service.Probes[0].Expect.RedirectHosts[0] = "changed.example"
			service.Probes[0].Expect.ContentTypes[0] = "application/json"
			service.Probes[0].Expect.BodyContains[0] = "changed"
			frozen, err = dataplane.FrozenProbeService(route)
			if err != nil || !reflect.DeepEqual(frozen, expected) {
				t.Fatal("editor changed frozen canary predicate", err)
			}
			if !errors.Is(binding.guard(a, ctx), dataplane.ErrReviewChanged) || !reflect.DeepEqual(cfg, a.Store.Get()) {
				t.Fatal("catalog drift escaped review or mutated settings")
			}
		})
	}
}
