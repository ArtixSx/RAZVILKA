package app

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/customservices"
)

func TestCustomServiceDeleteCannotOverlapSharedProfileImportWriter(t *testing.T) {
	a, _ := awgAPITest(t)
	var err error
	a.CustomServices, err = customservices.Load(filepath.Join(t.TempDir(), "custom.json"))
	if err != nil {
		t.Fatal(err)
	}
	service, err := a.CustomServices.Create(catalog.Service{ID: "import-race", Name: "Import race", Domains: []string{"import.example"}, Strategy: []string{"nfqws2"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Store.UpdateService(service.ID, config.ServiceState{Enabled: false, Route: "nfqws2"}); err != nil {
		t.Fatal(err)
	}
	a.AdmissionPatience = 25 * time.Millisecond
	entered, resume, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var once sync.Once
	defer once.Do(func() { close(resume) })
	profile := httptest.NewRecorder()
	handler := a.operationMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/profiles/import" {
			// The real shared request owns admission across its eventual Store
			// publication, just as profileImport's MergeDraft does in production.
			close(entered)
			<-resume
			if err := a.Store.MergeDraft(map[string]config.ServiceState{service.ID: {Enabled: true, Route: "nfqws2"}}); err != nil {
				http.Error(w, err.Error(), 500)
				return
			}
			w.WriteHeader(200)
			return
		}
		a.customServiceItem(w, r)
	}))
	go func() {
		defer close(done)
		handler.ServeHTTP(profile, httptest.NewRequest(http.MethodPost, "/api/v1/profiles/import", nil))
	}()
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("profile writer not admitted")
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodDelete, "/api/v1/custom-services/"+service.ID, nil))
	if response.Code != http.StatusConflict || !strings.Contains(response.Body.String(), "RESTORE_OPERATION_BUSY") || !a.CustomServices.Has(service.ID) {
		t.Fatalf("delete overlapped held profile writer: %d %s", response.Code, response.Body.String())
	}
	once.Do(func() { close(resume) })
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("profile writer did not join")
	}
	if profile.Code != 200 || !a.Store.Get().Services[service.ID].Enabled {
		t.Fatal("new imported draft was lost", profile.Body.String())
	}
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodDelete, "/api/v1/custom-services/"+service.ID, nil))
	if response.Code != http.StatusConflict || !strings.Contains(response.Body.String(), "CUSTOM_SERVICE_ROUTE_ACTIVE") || !a.CustomServices.Has(service.ID) {
		t.Fatalf("fresh active draft was deleted: %d %s", response.Code, response.Body.String())
	}
	if release, err := a.Operations.Exclusive(context.Background()); err != nil {
		t.Fatal("request leaked admission", err)
	} else {
		release()
	}
}

func TestCustomServiceDeleteCannotDeleteBuiltInDefinitionOrAssignment(t *testing.T) {
	a, send := awgAPITest(t)
	var err error
	a.CustomServices, err = customservices.Load(filepath.Join(t.TempDir(), "custom.json"))
	if err != nil {
		t.Fatal(err)
	}
	const id = "builtin-protected"
	a.Catalog.Services = append(a.Catalog.Services, catalog.Service{ID: id, Name: "Built in", Domains: []string{"builtin.example"}})
	if err := a.Store.UpdateService(id, config.ServiceState{Enabled: true, Route: "nfqws2"}); err != nil {
		t.Fatal(err)
	}
	before := a.Store.Get()
	w := send(http.MethodDelete, "/api/v1/custom-services/"+id, nil)
	if w.Code != http.StatusNotFound || a.Store.Get().Revision != before.Revision || !a.Store.Get().Services[id].Enabled {
		t.Fatalf("builtin assignment changed: %d %s", w.Code, w.Body.String())
	}
	if _, ok := a.autonomyService(id); !ok {
		t.Fatal("builtin definition disappeared")
	}
}
