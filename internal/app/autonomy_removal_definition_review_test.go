package app

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/customservices"
)

func TestAutonomyDeleteDefinitionRequiresFreshConfirmationAfterDefinitionEdit(t *testing.T) {
	a, _, adapter := autonomousIntegrationFixture(t)
	var err error
	a.CustomServices, err = customservices.Load(filepath.Join(t.TempDir(), "custom.json"))
	if err != nil {
		t.Fatal(err)
	}
	service, err := a.CustomServices.Create(catalog.Service{ID: "definition-delete", Name: "Delete definition", Domains: []string{"before.example"}, Strategy: []string{"nfqws2"}}, a.reservedServiceIDs())
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Store.UpdateService(service.ID, config.ServiceState{Enabled: true, Route: "auto"}); err != nil {
		t.Fatal(err)
	}
	if err := a.inheritAutonomyService(context.Background(), service.ID); err != nil {
		t.Fatal(err)
	}
	// Keep the unrelated fixture service out of this no-network removal round.
	a.autonomy.mu.Lock()
	other := a.autonomy.doc.Runtime["my-independent-site"]
	other.NextCheck = time.Now().Add(time.Hour)
	a.autonomy.doc.Runtime["my-independent-site"] = other
	err = a.persistAutonomyLocked(context.Background())
	a.autonomy.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	request := func(revision uint64) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		a.autonomyRemove(w, autonomyRequest(http.MethodDelete, "/api/v1/autonomy/services/"+service.ID, map[string]any{"expected_revision": revision, "confirm": "REMOVE_SERVICE", "delete_definition": true}))
		return w
	}
	initialRevision := a.autonomyPolicy().Revision
	if w := request(initialRevision); w.Code != http.StatusAccepted {
		t.Fatal(w.Code, w.Body.String())
	}
	service.Domains = []string{"after.example"}
	updated, err := a.CustomServices.Update(service.ID, service)
	if err != nil {
		t.Fatal(err)
	}
	before := a.Store.Get()
	a.autonomyRound(context.Background(), time.Now())
	a.autonomy.mu.Lock()
	state := a.autonomy.doc.Runtime[service.ID]
	a.autonomy.mu.Unlock()
	if state.State != "definition-changed" || !a.CustomServices.Has(service.ID) || !reflect.DeepEqual(before, a.Store.Get()) || len(adapter.calls) != 0 {
		t.Fatal("post-request edit was deleted or started runtime", state.State, adapter.calls)
	}
	if w := request(initialRevision); w.Code != http.StatusConflict {
		t.Fatal("stale confirmation accepted", w.Code, w.Body.String())
	}
	if w := request(a.autonomyPolicy().Revision); w.Code != http.StatusAccepted {
		t.Fatal("fresh delete could not be queued", w.Code, w.Body.String())
	}
	a.autonomy.mu.Lock()
	spec := a.autonomy.doc.Services[service.ID]
	a.autonomy.mu.Unlock()
	if spec.Definition != autonomyDefinition(updated) {
		t.Fatal("fresh explicit delete retained old definition")
	}
	a.autonomyRound(context.Background(), time.Now())
	if a.CustomServices.Has(service.ID) {
		t.Fatal("freshly confirmed definition was not removed")
	}
	if _, ok := a.Store.Get().Services[service.ID]; ok {
		t.Fatal("removed definition retained draft")
	}
	a.autonomy.mu.Lock()
	_, pending := a.autonomy.doc.Services[service.ID]
	a.autonomy.mu.Unlock()
	if pending || len(adapter.calls) != 0 {
		t.Fatal("confirmed unapplied removal remained pending or invoked runtime")
	}
}

func TestAutonomyDeleteDefinitionNeverRemovesBuiltInCatalogEntry(t *testing.T) {
	a, _, adapter := autonomousIntegrationFixture(t)
	const id = "my-independent-site"
	before := append([]catalog.Service(nil), a.Catalog.Services...)
	w := httptest.NewRecorder()
	a.autonomyRemove(w, autonomyRequest(http.MethodDelete, "/api/v1/autonomy/services/"+id, map[string]any{"expected_revision": a.autonomyPolicy().Revision, "confirm": "REMOVE_SERVICE", "delete_definition": true}))
	if w.Code != http.StatusAccepted {
		t.Fatal(w.Code, w.Body.String())
	}
	a.autonomyRound(context.Background(), time.Now())
	if !reflect.DeepEqual(before, a.Catalog.Services) {
		t.Fatal("built-in catalog changed")
	}
	if _, ok := a.autonomyService(id); !ok {
		t.Fatal("built-in definition was deleted")
	}
	if len(adapter.calls) != 0 {
		t.Fatal("unapplied removal invoked runtime", adapter.calls)
	}
}
