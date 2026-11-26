package app

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/dataplane"
)

// Uses the ordinary App plan builder and real catalog predicate validator.
// Node proof and OS adapters remain modeled; this is not native Apply evidence.
func TestOrdinaryNodePlanFreezesCatalogServicePredicate(t *testing.T) {
	engine := "xray"
	a, id, sing, xray := xrayRouteFixture(t, true)
	service := &a.Catalog.Services[0]
	service.Probes = []catalog.Probe{{
		ID: "telegram-web", Label: "Telegram web", URL: service.ProbeURL, Required: true,
		Expect: catalog.ProbeExpectation{
			StatusCodes: []int{200}, RedirectPolicy: "allowlist",
			RedirectHosts: []string{"telegram.org"}, ContentTypes: []string{"text/html"},
			BodyContains: []string{"Telegram"},
		},
	}}
	expectedService := defaultRouteCloneCatalogService(*service)
	before := a.Store.Get()
	target := nodeRouteConfigForEngineScope(before, engine, "telegram", id, []string{"192.168.1.40/32"})
	plan, err := a.buildDataplanePlanForScopeContext(context.Background(), target, a.nodeRouteOptions(), changeScopeNode, "")
	if err != nil || len(plan.Routes) != 1 || plan.Routes[0].Resolved != engine+":"+id {
		t.Fatalf("ordinary exact node plan: routes=%+v err=%v", plan.Routes, err)
	}
	route := plan.Routes[0]
	frozen, err := dataplane.FrozenProbeService(route)
	if err != nil || route.LogicalServiceID != "telegram" || !reflect.DeepEqual(frozen, expectedService) {
		t.Fatalf("runtime cannot consume the catalog predicate: service=%+v err=%v", frozen, err)
	}
	binding, err := a.bindApplyReview(context.Background(), before, plan, changeScopeNode, "")
	if err != nil {
		t.Fatal(err)
	}
	// Changing a nested expectation cannot rewrite the reviewed plan,
	// and the existing catalog guard must refuse its use before effects.
	service.Probes[0].Expect.StatusCodes[0] = 403
	service.Probes[0].Expect.RedirectHosts[0] = "changed.example"
	service.Probes[0].Expect.ContentTypes[0] = "application/json"
	service.Probes[0].Expect.BodyContains[0] = "changed"
	frozen, err = dataplane.FrozenProbeService(route)
	if err != nil || !reflect.DeepEqual(frozen, expectedService) {
		t.Fatal("catalog mutation changed the reviewed predicate", err)
	}
	if !errors.Is(binding.guard(a, context.Background()), dataplane.ErrReviewChanged) {
		t.Fatal("catalog drift escaped the existing review guard")
	}
	if len(sing.calls) != 0 || len(xray.calls) != 0 || !reflect.DeepEqual(before, a.Store.Get()) {
		t.Fatal("plan or refused review changed runtime/configuration")
	}
}
