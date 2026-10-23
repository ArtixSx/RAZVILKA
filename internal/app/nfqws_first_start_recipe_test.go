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
	if get.Code != 200 || !reflect.DeepEqual(before, s.Get()) {
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
	cfg.NFQWSFirstStartRecipe = engineconfig.NFQWSFirstStartStockTLSCircular
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
	body := fmt.Sprintf(`{"recipe":%q,"expected_revision":%d}`, engineconfig.NFQWSFirstStartStockTLSCircular, s.Get().Revision)
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
	if w := request(http.MethodPut, "http://router.local", panelTestToken, body); w.Code != 200 || s.Get().AppliedNFQWSFirstStartRecipe != "" {
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
