package app

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/ArtixSx/razvilka/internal/autonomy"
	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/config"
)

func autonomyAPIFixture(t *testing.T) *App {
	t.Helper()
	store, err := config.Load(filepath.Join(t.TempDir(), "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	return &App{Store: store, Catalog: catalog.Catalog{Services: []catalog.Service{{ID: "arbitrary-site", Name: "Arbitrary Site", Domains: []string{"example.org"}, ProbeURL: "https://example.org/"}}}}
}
func autonomyRequest(method, path string, body any) *http.Request {
	data, _ := json.Marshal(body)
	return httptest.NewRequest(method, path, bytes.NewReader(data))
}
func saveAutonomyFixturePolicy(t *testing.T, a *App) autonomy.Policy {
	t.Helper()
	p := autonomy.Default()
	p.Enabled = true
	p.SetupComplete = true
	p.DefaultSources = []string{"192.168.1.50/32"}
	p.SourceIDs = []string{"feed-goida-extra"}
	p.InheritNewServices = true
	w := httptest.NewRecorder()
	a.autonomyAPI(w, autonomyRequest("PUT", "/api/v1/autonomy", map[string]any{"expected_revision": 0, "policy": p, "confirm": "SAVE_AUTONOMY", "release_safe_mode": false}))
	if w.Code != 200 {
		t.Fatalf("policy save failed: %d %s", w.Code, w.Body.String())
	}
	return a.autonomyPolicy()
}
func TestAutonomyAPIReadOnlyAndCAS(t *testing.T) {
	a := autonomyAPIFixture(t)
	before := a.Store.Get()
	w := httptest.NewRecorder()
	a.autonomyAPI(w, httptest.NewRequest("GET", "/api/v1/autonomy", nil))
	if w.Code != 200 || !reflect.DeepEqual(before, a.Store.Get()) {
		t.Fatal("read changed configuration")
	}
	p := saveAutonomyFixturePolicy(t, a)
	if !a.Store.Get().SafeMode {
		t.Fatal("wizard silently removed Safe Mode")
	}
	w = httptest.NewRecorder()
	a.autonomyAPI(w, autonomyRequest("PUT", "/api/v1/autonomy", map[string]any{"expected_revision": 0, "policy": p, "confirm": "SAVE_AUTONOMY"}))
	if w.Code != 409 {
		t.Fatal("stale policy accepted", w.Code)
	}
	if a.autonomyPolicy().Revision != p.Revision {
		t.Fatal("CAS changed revision")
	}
}
func TestAutonomyExplicitInheritanceAndQueuedRemoval(t *testing.T) {
	a := autonomyAPIFixture(t)
	saveAutonomyFixturePolicy(t, a)
	before := a.Store.Get()
	if err := a.inheritAutonomyService(context.Background(), "arbitrary-site"); err != nil {
		t.Fatal(err)
	}
	a.autonomy.mu.Lock()
	s, ok := a.autonomy.doc.Services["arbitrary-site"]
	a.autonomy.mu.Unlock()
	if !ok || !s.Enabled || !reflect.DeepEqual(s.Sources, []string{"192.168.1.50/32"}) || !reflect.DeepEqual(before, a.Store.Get()) {
		t.Fatal("inheritance applied without checks or lost scope")
	}
	revision := a.autonomyPolicy().Revision
	if err := a.inheritAutonomyService(context.Background(), "arbitrary-site"); err != nil || a.autonomyPolicy().Revision != revision {
		t.Fatal("inheritance not idempotent")
	}
	w := httptest.NewRecorder()
	a.autonomyRemove(w, autonomyRequest("DELETE", "/api/v1/autonomy/services/arbitrary-site", map[string]any{"expected_revision": revision, "confirm": "REMOVE_SERVICE", "delete_definition": false}))
	if w.Code != 202 || !reflect.DeepEqual(before, a.Store.Get()) {
		t.Fatal("removal bypassed transaction", w.Code)
	}
	a.autonomy.mu.Lock()
	removing := a.autonomy.doc.Services["arbitrary-site"].Removing
	a.autonomy.mu.Unlock()
	if !removing {
		t.Fatal("removal not persisted")
	}
}
func TestAutonomyRejectsUnknownSourceAndInstallMode(t *testing.T) {
	for _, what := range []string{"source", "install"} {
		t.Run(what, func(t *testing.T) {
			a := autonomyAPIFixture(t)
			p := autonomy.Default()
			p.SetupComplete = true
			p.Enabled = true
			p.AllLAN = true
			p.SourceIDs = []string{"feed-goida-extra"}
			if what == "source" {
				p.SourceIDs = []string{"not-in-registry"}
			} else {
				p.Application.Mode = "install"
			}
			w := httptest.NewRecorder()
			a.autonomyAPI(w, autonomyRequest("PUT", "/api/v1/autonomy", map[string]any{"expected_revision": 0, "policy": p, "confirm": "SAVE_AUTONOMY"}))
			if w.Code != 400 {
				t.Fatal("unsupported authority accepted", w.Code)
			}
		})
	}
}
func TestAutonomyDiskChangeRevokesCachedConsent(t *testing.T) {
	a := autonomyAPIFixture(t)
	saveAutonomyFixturePolicy(t, a)
	if err := os.WriteFile(a.autonomy.path, []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	if a.autonomyDiskCurrent(context.Background()) == nil || !a.autonomy.blocked {
		t.Fatal("replaced consent remained valid")
	}
}
func TestAutonomyMalformedSidecarFailsClosed(t *testing.T) {
	a := autonomyAPIFixture(t)
	path := a.Store.AutomationStatePath() + ".autonomy.json"
	if err := os.WriteFile(path, []byte(`{"schema":1,"owner":"other"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if a.loadAutonomy(context.Background()) == nil || !a.autonomy.blocked {
		t.Fatal("malformed consent accepted")
	}
}
