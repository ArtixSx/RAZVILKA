package app

import (
	"context"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/ArtixSx/razvilka/internal/config"
)

func TestServiceRouteRepairReviewPreservesEngineDraftAndStoppedScope(t *testing.T) {
	a := genericReviewFixture(t)
	if err := a.Store.UpdateService("telegram", config.ServiceState{Enabled: true, Route: "direct", Sources: []string{"192.168.1.40/32"}}); err != nil {
		t.Fatal(err)
	}
	if err := a.Store.ApplyDraft(); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Store.CommitServiceRuntime(true, map[string]string{"telegram": "direct"}, a.Store.Get().Revision); err != nil {
		t.Fatal(err)
	}
	// A separate device edit must remain pending while restoring the route.
	if err := a.Store.UpdateService("telegram", config.ServiceState{Enabled: true, Route: "nfqws2"}); err != nil {
		t.Fatal(err)
	}
	const draft = "pending.example\n"
	if _, err := a.EngineConfigs.Stage("nfqws2", "user-list", draft); err != nil {
		t.Fatal(err)
	}
	before := a.Store.Get()
	query := "?scope=services&engine_drafts=preserve"
	r := httptest.NewRequest("GET", "/api/v1/plan"+query, nil)
	plan, err := a.buildDataplanePlanForRequest(before, a.routeOptionsSnapshot(), changeScopeServices, "", r)
	if err != nil || len(plan.EngineDrafts) != 0 || len(plan.Routes) != 1 || !reflect.DeepEqual(plan.Routes[0].Sources, []string{"192.168.1.40/32"}) {
		t.Fatalf("repair changed draft/scope: %v %+v", err, plan)
	}
	normal, err := a.buildDataplanePlanForScope(before, a.routeOptionsSnapshot(), changeScopeServices, "")
	if err != nil || !reflect.DeepEqual(normal.EngineDrafts, []string{"nfqws2/user-list"}) || normal.Digest == plan.Digest {
		t.Fatal("review does not bind the engine-draft choice", err)
	}
	review := genericReviewed(t, a, query)
	if w := genericApply(a, "?scope=services", review); w.Code != 409 || !strings.Contains(w.Body.String(), "APPLY_REVIEW_CHANGED") {
		t.Fatal("preserved-draft review authorized a different plan", w.Code, w.Body.String())
	}
	binding, err := a.bindApplyReview(context.Background(), before, plan, changeScopeServices, "")
	if err != nil {
		t.Fatal(err)
	}
	undo, err := binding.commit(a, context.Background(), changeScopeServices)
	if err != nil {
		t.Fatal(err)
	}
	after := a.Store.Get()
	if after.ServiceControl.Stopped || !reflect.DeepEqual(after.Services, before.Services) || !reflect.DeepEqual(after.AppliedServices["telegram"].Sources, []string{"192.168.1.40/32"}) {
		t.Fatal("route commit widened scope or consumed desired device edit")
	}
	if view, err := a.EngineConfigs.ReadExpert("nfqws2", "user-list"); err != nil || view.Source != "staged" || view.Content != draft {
		t.Fatal("route commit consumed engine draft", err)
	}
	if err := undo(); err != nil || !reflect.DeepEqual(a.Store.Get(), before) {
		t.Fatal("route repair cannot restore stopped snapshot", err)
	}
}

func TestServiceRouteRepairRejectsAmbiguousOrUnrelatedDraftMode(t *testing.T) {
	for _, query := range []string{"?scope=services&engine_drafts=unknown", "?scope=engine&engine=nfqws2&engine_drafts=preserve", "?engine_drafts=preserve", "?scope=services&engine_drafts=preserve&engine_drafts=preserve"} {
		a := genericReviewFixture(t)
		w := httptest.NewRecorder()
		a.plan(w, httptest.NewRequest("GET", "/api/v1/plan"+query, nil))
		if w.Code != 400 {
			t.Fatal(query, w.Code, w.Body.String())
		}
	}
}
