package app

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/engineconfig"
	"github.com/ArtixSx/razvilka/internal/security"
)

func TestNFQWSFirstStartRecipeAPIStagesOnlyExplicitKnownRevision(t *testing.T) {
	s, err := config.Load(filepath.Join(t.TempDir(), "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	a := &App{Store: s}
	before := s.Get()
	get := httptest.NewRecorder()
	a.nfqwsFirstStartRecipe(get, httptest.NewRequest(http.MethodGet, "/api/v1/nfqws2/first-start-recipe", nil))
	if get.Code != 200 || !reflect.DeepEqual(before, s.Get()) || !strings.Contains(get.Body.String(), `"id":"stock-tls-circular-auto-v1"`) {
		t.Fatal("GET changed intent", get.Code)
	}
	for _, body := range []string{`{"recipe":"unknown","expected_revision":0}`, `{"expected_revision":0}`, `{"recipe":null,"expected_revision":0}`, `{"recipe":""}`, `{"recipe":"","expected_revision":0,"arguments":"--filter-tcp=80"}`} {
		r := httptest.NewRecorder()
		a.nfqwsFirstStartRecipe(r, httptest.NewRequest(http.MethodPut, "/api/v1/nfqws2/first-start-recipe", strings.NewReader(body)))
		if r.Code != 400 || !reflect.DeepEqual(before, s.Get()) {
			t.Fatal("invalid selection changed intent", body, r.Code)
		}
	}
	body := fmt.Sprintf(`{"recipe":%q,"expected_revision":%d}`, engineconfig.NFQWSFirstStartStockTLSCircular, before.Revision)
	r := httptest.NewRecorder()
	a.nfqwsFirstStartRecipe(r, httptest.NewRequest(http.MethodPut, "/api/v1/nfqws2/first-start-recipe", strings.NewReader(body)))
	if r.Code != 200 || s.Get().NFQWSFirstStartRecipe != engineconfig.NFQWSFirstStartStockTLSCircular || s.Get().AppliedNFQWSFirstStartRecipe != "" || !strings.Contains(r.Body.String(), `"live_applied":false`) {
		t.Fatal("selection applied runtime or failed", r.Code, r.Body.String())
	}
	staged := s.Get()
	r = httptest.NewRecorder()
	a.nfqwsFirstStartRecipe(r, httptest.NewRequest(http.MethodPut, "/api/v1/nfqws2/first-start-recipe", strings.NewReader(body)))
	if r.Code != 409 || !reflect.DeepEqual(staged, s.Get()) {
		t.Fatal("stale selection accepted", r.Code)
	}
}

func TestNFQWSFirstStartRecipeScopeDoesNotLeakPendingChoice(t *testing.T) {
	cfg := config.Default()
	cfg.NFQWSFirstStartRecipe = engineconfig.NFQWSFirstStartStockTLSCircularAuto
	for _, scope := range []changeScope{changeScopeAll, changeScopeRouting, changeScopeServices, changeScopeDevices, changeScopeEngine, changeScopeExclusions, changeScopeNode} {
		got := configForChangeScope(cfg, scope)
		want := engineconfig.NFQWSFirstStartRecipe("")
		if scope == changeScopeAll || scope == changeScopeRouting || scope == changeScopeServices {
			want = cfg.NFQWSFirstStartRecipe
		}
		if got.NFQWSFirstStartRecipe != want {
			t.Fatal("pending recipe escaped its scope", scope)
		}
	}
}

func TestNFQWSFirstStartRecipeHandlerKeepsAuthCASAndExclusiveAdmission(t *testing.T) {
	s, err := config.Load(filepath.Join(t.TempDir(), "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	gate, err := security.NewGate(panelTestToken)
	if err != nil {
		t.Fatal(err)
	}
	a := &App{Store: s, Security: gate}
	handler := a.Handler(http.NotFoundHandler())
	request := func(method, origin, token, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, "http://router.local/api/v1/nfqws2/first-start-recipe", strings.NewReader(body))
		r.Header.Set("Origin", origin)
		r.Header.Set("Content-Type", "application/json")
		if token != "" {
			r.Header.Set("Authorization", "Bearer "+token)
		}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w
	}
	body := fmt.Sprintf(`{"recipe":%q,"expected_revision":%d}`, engineconfig.NFQWSFirstStartStockTLSCircularAuto, s.Get().Revision)
	before := s.Get()
	if w := request(http.MethodPut, "http://router.local", "", body); w.Code != 401 {
		t.Fatal("unauthenticated write", w.Code)
	}
	if w := request(http.MethodPut, "https://foreign.invalid", panelTestToken, body); w.Code != 403 {
		t.Fatal("cross-origin write", w.Code)
	}
	if w := request(http.MethodGet, "http://router.local", panelTestToken, ""); w.Code != 200 || !reflect.DeepEqual(before, s.Get()) {
		t.Fatal("GET not read-only", w.Code)
	}
	release, err := a.Operations.Enter(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	if w := request(http.MethodPut, "http://router.local", panelTestToken, body); w.Code != 409 || !reflect.DeepEqual(before, s.Get()) {
		t.Fatal("recipe write bypassed exclusive admission", w.Code, w.Body.String())
	}
	release()
	if w := request(http.MethodPut, "http://router.local", panelTestToken, body); w.Code != 200 || s.Get().NFQWSFirstStartRecipe != engineconfig.NFQWSFirstStartStockTLSCircularAuto || s.Get().AppliedNFQWSFirstStartRecipe != "" {
		t.Fatal("authenticated draft selection failed or applied live", w.Code, w.Body.String())
	}
	staged := s.Get()
	if w := request(http.MethodPut, "http://router.local", panelTestToken, body); w.Code != 409 || !reflect.DeepEqual(staged, s.Get()) {
		t.Fatal("CAS guard lost through Handler", w.Code)
	}
	a.Operations.FenceJournal()
	body = fmt.Sprintf(`{"recipe":"","expected_revision":%d}`, s.Get().Revision)
	if w := request(http.MethodPut, "http://router.local", panelTestToken, body); w.Code != 503 || !reflect.DeepEqual(staged, s.Get()) {
		t.Fatal("fenced operation admitted draft write", w.Code)
	}
}

func TestNFQWSFirstStartRecipeNodeAndRemovalHypotheticalKeepsAppliedChoice(t *testing.T) {
	for _, applied := range []engineconfig.NFQWSFirstStartRecipe{"", engineconfig.NFQWSFirstStartStockTLSCircular} {
		before := config.Default()
		before.AppliedNFQWSFirstStartRecipe = applied
		before.NFQWSFirstStartRecipe = engineconfig.NFQWSFirstStartStockTLSCircular
		if applied != "" {
			before.NFQWSFirstStartRecipe = ""
		}
		for _, engine := range []string{"sing-box", "xray"} {
			next := nodeRouteConfigForEngineScope(before, engine, "target", "node-fixture", nil)
			if next.NFQWSFirstStartRecipe != applied || next.AppliedNFQWSFirstStartRecipe != applied || before.NFQWSFirstStartRecipe == applied {
				t.Fatal("node hypothesis consumed pending recipe", engine)
			}
		}
		// Autonomy removal uses this same applied-services hypothetical, then
		// disables only the target route before planning its removal.
		next := nodeRouteConfigForScope(before, "target", "unused", nil)
		target := next.Services["target"]
		target.Enabled = false
		next.Services["target"] = target
		if next.NFQWSFirstStartRecipe != applied || before.NFQWSFirstStartRecipe == applied {
			t.Fatal("removal hypothesis consumed pending recipe")
		}
	}
}

func TestNFQWSFirstStartRecipePreservedEngineDraftPlanMatchesServicesCommit(t *testing.T) {
	for _, applied := range []engineconfig.NFQWSFirstStartRecipe{"", engineconfig.NFQWSFirstStartStockTLSCircular} {
		a := genericReviewFixture(t)
		if err := a.Store.SetNFQWSFirstStartRecipe(a.Store.Get().Revision, applied); err != nil {
			t.Fatal(err)
		}
		if err := a.Store.ApplyDraft(); err != nil {
			t.Fatal(err)
		}
		desired := engineconfig.NFQWSFirstStartStockTLSCircular
		if applied != "" {
			desired = ""
		}
		if err := a.Store.SetNFQWSFirstStartRecipe(a.Store.Get().Revision, desired); err != nil {
			t.Fatal(err)
		}
		if err := a.Store.UpdateService("telegram", config.ServiceState{Enabled: true, Route: "nfqws2"}); err != nil {
			t.Fatal(err)
		}
		const draft = "pending.example\n"
		if _, err := a.EngineConfigs.Stage("nfqws2", "user-list", draft); err != nil {
			t.Fatal(err)
		}
		before := a.Store.Get()
		r := httptest.NewRequest("GET", "/api/v1/plan?scope=services&engine_drafts=preserve", nil)
		plan, err := a.buildDataplanePlanForRequest(before, a.routeOptionsSnapshot(), changeScopeServices, "", r)
		if err != nil || len(plan.EngineDrafts) != 0 {
			t.Fatal("preserved-draft plan failed", err)
		}
		binding, err := a.bindApplyReview(context.Background(), before, plan, changeScopeServices, "")
		if err != nil {
			t.Fatal(err)
		}
		undo, err := binding.commit(a, context.Background(), changeScopeServices)
		if err != nil {
			t.Fatal(err)
		}
		if plan.NFQWSFirstStartRecipe != a.Store.Get().AppliedNFQWSFirstStartRecipe || plan.NFQWSFirstStartRecipe != desired {
			t.Fatal("preserved engine-draft plan recipe differs from service commit", plan.NFQWSFirstStartRecipe, a.Store.Get().AppliedNFQWSFirstStartRecipe)
		}
		if view, err := a.EngineConfigs.ReadExpert("nfqws2", "user-list"); err != nil || view.Source != "staged" || view.Content != draft {
			t.Fatal("recipe commit consumed engine draft", err)
		}
		if err := undo(); err != nil || !reflect.DeepEqual(a.Store.Get(), before) {
			t.Fatal("recipe commit rollback lost original intent", err)
		}
	}
}

func TestNFQWSFirstStartObserverRecipeAPIOnlyStagesDraft(t *testing.T) {
	s, err := config.Load(filepath.Join(t.TempDir(), "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	a := &App{Store: s}
	before := s.Get()
	get := httptest.NewRecorder()
	a.nfqwsFirstStartRecipe(get, httptest.NewRequest(http.MethodGet, "/api/v1/nfqws2/first-start-recipe", nil))
	if get.Code != 200 || !strings.Contains(get.Body.String(), string(engineconfig.NFQWSFirstStartStockTLSCircularObserveAuto)) {
		t.Fatal("observer recipe absent")
	}
	body := fmt.Sprintf(`{"recipe":%q,"expected_revision":%d}`, engineconfig.NFQWSFirstStartStockTLSCircularObserveAuto, before.Revision)
	put := httptest.NewRecorder()
	a.nfqwsFirstStartRecipe(put, httptest.NewRequest(http.MethodPut, "/api/v1/nfqws2/first-start-recipe", strings.NewReader(body)))
	after := s.Get()
	if put.Code != 200 || after.NFQWSFirstStartRecipe != engineconfig.NFQWSFirstStartStockTLSCircularObserveAuto || after.AppliedNFQWSFirstStartRecipe != before.AppliedNFQWSFirstStartRecipe || !strings.Contains(put.Body.String(), `"live_applied":false`) {
		t.Fatal("recipe did not remain draft", put.Code)
	}
	if !reflect.DeepEqual(after.AppliedServices, before.AppliedServices) || !reflect.DeepEqual(after.Services, before.Services) || after.ServiceControl.Stopped != before.ServiceControl.Stopped || after.SafeMode != before.SafeMode {
		t.Fatal("recipe changed runtime or desired services")
	}
	stale := httptest.NewRecorder()
	a.nfqwsFirstStartRecipe(stale, httptest.NewRequest(http.MethodPut, "/api/v1/nfqws2/first-start-recipe", strings.NewReader(body)))
	if stale.Code != 409 || !reflect.DeepEqual(after, s.Get()) {
		t.Fatal("stale observer choice changed intent")
	}
}
