package app

import (
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/customservices"
)

func TestCustomServiceDeleteRequiresDesiredAndAppliedRouteRemoval(t *testing.T) {
	for _, state := range []string{"desired-active", "applied-active", "disabled-unapplied"} {
		t.Run(state, func(t *testing.T) {
			a, send := awgAPITest(t)
			var err error
			a.CustomServices, err = customservices.Load(filepath.Join(t.TempDir(), "custom.json"))
			if err != nil {
				t.Fatal(err)
			}
			service, err := a.CustomServices.Create(catalog.Service{ID: "delete-guard", Name: "Delete guard", Domains: []string{"delete.example"}, Strategy: []string{"nfqws2"}}, nil)
			if err != nil {
				t.Fatal(err)
			}
			if err := a.Store.UpdateService(service.ID, config.ServiceState{Enabled: state != "disabled-unapplied", Route: "nfqws2"}); err != nil {
				t.Fatal(err)
			}
			if state == "applied-active" {
				if err := a.Store.ApplyDraft(); err != nil {
					t.Fatal(err)
				}
				if err := a.Store.UpdateService(service.ID, config.ServiceState{Enabled: false, Route: "nfqws2"}); err != nil {
					t.Fatal(err)
				}
			}
			response := send(http.MethodDelete, "/api/v1/custom-services/"+service.ID, nil)
			if state == "disabled-unapplied" {
				if response.Code != http.StatusOK || a.CustomServices.Has(service.ID) {
					t.Fatalf("%d %s", response.Code, response.Body.String())
				}
			} else if response.Code != http.StatusConflict || !a.CustomServices.Has(service.ID) || !strings.Contains(response.Body.String(), "Сначала отключите сервис") {
				t.Fatalf("%d %s", response.Code, response.Body.String())
			}
		})
	}
}
