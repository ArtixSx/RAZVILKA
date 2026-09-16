package app

import (
	"context"
	"encoding/json"
	"github.com/ArtixSx/razvilka/internal/autonomy"
	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/community"
	"github.com/ArtixSx/razvilka/internal/customservices"
	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/evidence"
	"github.com/ArtixSx/razvilka/internal/onboarding"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestRepair2FirstSetupEnrolsBaseAndSelectedExtrasPersistsNoApply(t *testing.T) {
	a := autonomyAPIFixture(t)
	extra := a.Catalog.Services[0]
	a.Catalog = catalog.NFQWS2Starter()
	a.Catalog.Services = append(a.Catalog.Services, extra)
	before := a.Store.Get()
	w := httptest.NewRecorder()
	a.autonomyAPI(w, autonomyRequest("GET", "/api/v1/autonomy", nil))
	var view struct {
		Starter onboarding.StarterReview `json:"starter"`
	}
	if json.Unmarshal(w.Body.Bytes(), &view) != nil || !view.Starter.Eligible {
		t.Fatal(w.Body.String())
	}
	p := autonomy.Default()
	p.SetupComplete = true
	p.Enabled = true
	p.AllLAN = true
	p.PreferredRoutes = []string{"nfqws2"}
	w = httptest.NewRecorder()
	a.autonomyAPI(w, autonomyRequest("PUT", "/api/v1/autonomy", map[string]any{"expected_revision": 0, "policy": p, "confirm": "SAVE_AUTONOMY", "starter_sha256": view.Starter.SHA256, "initial_service_ids": []string{extra.ID}}))
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	if !reflect.DeepEqual(before, a.Store.Get()) || len(a.autonomy.doc.Services) != 7 {
		t.Fatal("unexpected live change or missing selected definitions")
	}
	fresh := &App{Store: a.Store, Catalog: a.Catalog}
	if fresh.loadAutonomy(context.Background()) != nil || len(fresh.autonomy.doc.Services) != 7 || !fresh.autonomy.doc.Policy.SetupComplete {
		t.Fatal("setup lost on reload")
	}
	for id, s := range fresh.autonomy.doc.Services {
		want := "nfqws2"
		if id == extra.ID {
			want = "auto"
		}
		if s.ExpectedRoute != want {
			t.Fatal("unexpected route", id, s)
		}
	}
	w = httptest.NewRecorder()
	a.autonomyAPI(w, autonomyRequest("PUT", "/api/v1/autonomy", map[string]any{"expected_revision": 1, "policy": p, "confirm": "SAVE_AUTONOMY", "starter_sha256": view.Starter.SHA256}))
	if w.Code != 409 {
		t.Fatal("stale first setup accepted", w.Code)
	}
}
func TestRepair2CustomSourceAuthenticatedHTTPImportAndReload(t *testing.T) {
	a, send := awgAPITest(t)
	var err error
	a.Community, err = community.Load("../../configs/community-catalog.json")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "custom.json")
	a.CustomServices, err = customservices.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	before := a.Store.Get()
	w := send("POST", "/api/v1/community/source-preview", map[string]any{"name": "Private choice", "format": "domains", "content": "chosen.example\ncdn.chosen.example", "probe_url": "https://chosen.example/", "expected_revision": before.Revision, "confirm": "PREVIEW_SERVICE_SOURCE"})
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	var v community.Preview
	if json.Unmarshal(w.Body.Bytes(), &v) != nil || v.ImportGuard != "source-sha256" {
		t.Fatal(w.Body.String())
	}
	route := "/api/v1/community/services/" + v.Entry.ID + "/import"
	for _, sha := range []string{"", strings.Repeat("0", 64)} {
		w = send("POST", route, map[string]any{"expected_source_sha256": sha})
		if w.Code != 400 && w.Code != 409 {
			t.Fatal("unreviewed import", w.Code)
		}
	}
	w = send("POST", route, map[string]any{"expected_source_sha256": v.SourceSHA})
	if w.Code != 201 {
		t.Fatal(w.Code, w.Body.String())
	}
	if !reflect.DeepEqual(before, a.Store.Get()) {
		t.Fatal("passive import changed routes")
	}
	store, e := customservices.Load(path)
	if e != nil || !store.Has("custom-"+v.Entry.ID) {
		t.Fatal("definition not durable", e)
	}
	w = send("POST", route, map[string]any{"expected_source_sha256": v.SourceSHA})
	if w.Code != 200 {
		t.Fatal("repeat imported duplicate", w.Code, w.Body.String())
	}
}
func TestRepair2AmbiguousNodeSearchesReserveWithoutApply(t *testing.T) {
	a, ids, adapter := autonomousIntegrationFixture(t)
	a.NodeChecker = jobNodeChecker(func(_ context.Context, r dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
		return autofallbackResult(r, true), nil
	})
	a.autonomyRound(context.Background(), time.Now())
	before := a.Store.Get()
	current := strings.TrimPrefix(selectedRoute(before.AppliedServices["my-independent-site"]), "sing-box:")
	checked := []string{}
	adapter.calls = nil
	a.NodeChecker = jobNodeChecker(func(_ context.Context, r dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
		checked = append(checked, r.NodeID)
		x := autofallbackResult(r, true)
		if r.NodeID == current {
			x = autofallbackResult(r, false)
			x.Verdict = evidence.VerdictInconclusive
			x.Stage = "egress"
			x.ErrorCode = "node-direct-control-unavailable"
		}
		return x, nil
	})
	autonomyTestDue(a, false)
	a.autonomy.mu.Lock()
	r := a.autonomy.doc.Runtime["my-independent-site"]
	r.ReserveCheckedAt = time.Time{}
	a.autonomy.doc.Runtime["my-independent-site"] = r
	a.autonomy.mu.Unlock()
	a.autonomyRound(context.Background(), time.Now())
	if len(checked) < 2 || len(adapter.calls) != 0 || !reflect.DeepEqual(before, a.Store.Get()) || autonomyTestState(a).State != "unconfirmed" {
		t.Fatal("ambiguity starves reserve or applies without authority", checked, ids, adapter.calls, autonomyTestState(a))
	}
}
func TestRepair2UnsafeProbeStagesNeverExploreNeighbours(t *testing.T) {
	for _, stage := range []string{"cleanup", "route_identity", "configuration", "protocol", "dns", "deadline", "canceled", ""} {
		if canExploreUnconfirmedNode(dataplane.NodeCheckResult{Stage: stage, Verdict: evidence.VerdictInconclusive}) {
			t.Fatal("unsafe stage admitted", stage)
		}
	}
}
