package app

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/autonomy"
	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/customservices"
	"github.com/ArtixSx/razvilka/internal/dataplane"
)

func TestAutonomyRefreshesReenrolledCustomDomains(t *testing.T) {
	a, model, _ := autoNFQFirstStartFixture(t)
	var err error
	a.CustomServices, err = customservices.Load(filepath.Join(t.TempDir(), "custom.json"))
	if err != nil {
		t.Fatal(err)
	}
	// A separate active service must survive both edits and re-application.
	if r := runAutoNFQDispatcher(t, a, "discord", func() bool { return true }, nil); r.State != "applied" {
		t.Fatal(r)
	}
	a.RouteProber = confirmedRouteProber{}
	service := catalog.Service{ID: "custom-site", Name: "My site", Domains: []string{"www.example.org", "old.example.org"}, ProbeURL: "https://www.example.org/", Strategy: []string{"auto"}}
	created := httptest.NewRecorder()
	a.customServiceList(created, autonomyRequest(http.MethodPost, "/api/v1/custom-services", service))
	if created.Code != http.StatusCreated {
		t.Fatal(created.Code, created.Body)
	}
	if err := a.Store.UpdateService(service.ID, config.ServiceState{Enabled: true, Route: "auto"}); err != nil {
		t.Fatal(err)
	}
	review := func(changed bool) {
		t.Helper()
		w := httptest.NewRecorder()
		request := map[string]any{
			"service_id": service.ID, "enabled": true, "use_defaults": true, "expected_revision": a.autonomyPolicy().Revision, "confirm": "MANAGE_SERVICE",
		}
		if changed {
			current, _ := a.autonomyService(service.ID)
			request["confirm"], request["expected_definition"] = "REVIEW_SERVICE_DEFINITION", autonomyDefinition(current)
		}
		a.autonomyEnroll(w, autonomyRequest(http.MethodPost, "/api/v1/autonomy/services", request))
		if w.Code != http.StatusOK {
			t.Fatal(w.Code, w.Body)
		}
	}
	review(false)
	run := func() string { return runAutoNFQDispatcher(t, a, service.ID, nil, nil).State }
	if got := run(); got != "applied" {
		t.Fatal("first application:", got)
	}
	// The newest neighbor's first journal entry has no preceding AppliedRoute.
	if r := runAutoNFQDispatcher(t, a, "youtube", func() bool { return true }, nil); r.State != "applied" {
		t.Fatal(r)
	}
	before, _, err := a.Dataplane.Committed()
	if err != nil {
		t.Fatal(err)
	}
	service.Domains = []string{"www.example.org", "new.example.org"}
	edited := httptest.NewRecorder()
	a.customServiceItem(edited, autonomyRequest(http.MethodPut, "/api/v1/custom-services/"+service.ID, service))
	if edited.Code != http.StatusOK || run() != "definition-changed" {
		t.Fatal("custom edit did not require review", edited.Code, edited.Body)
	}
	review(true)
	model.calls = nil
	// A positive website probe may not replace an unobserved owner, spend an
	// exhausted budget, or bring an unrelated catalog edit into the transaction.
	model.committed = false
	if got := run(); got != "unconfirmed" || len(model.calls) != 0 {
		t.Fatal("unobserved runtime was treated as current", got, model.calls)
	}
	model.committed = true
	limited := runAutoNFQDispatcher(t, a, service.ID, nil, func(p *autonomy.Policy, _ *autonomy.Service, r *autonomy.Runtime, _ *context.Context) {
		for range p.MaxSwitchesPerHour {
			r.Switches = append(r.Switches, time.Now())
		}
	})
	if limited.State != "rate-limited" || !limited.NextCheck.After(time.Now()) || len(model.calls) != 0 {
		t.Fatal("exhausted budget led to Apply", limited, model.calls)
	}
	neighbor := slices.IndexFunc(a.Catalog.Services, func(s catalog.Service) bool { return s.ID == "discord" })
	oldNeighbor := a.Catalog.Services[neighbor]
	a.Catalog.Services[neighbor].Domains = append(slices.Clone(oldNeighbor.Domains), "neighbor.example.org")
	if got := run(); got != "apply-refused" || len(model.calls) != 0 {
		t.Fatal("an unapproved neighbor edit reached the adapter", got, model.calls)
	}
	held, _, err := a.Dataplane.Committed()
	if err != nil || !reflect.DeepEqual(held, before) {
		t.Fatal("an unsuccessful refresh changed the incumbent", err)
	}
	a.Catalog.Services[neighbor] = oldNeighbor
	if got := run(); got != "applied" || !slices.Contains(model.calls, "commit") {
		t.Fatalf("re-enrolled domain list was never applied: %s %v", got, model.calls)
	}
	after, _, err := a.Dataplane.Committed()
	current, _ := a.autonomyService(service.ID)
	if err != nil || !committedServiceCurrent(after, current) || len(before.Routes) != 3 || len(after.Routes) != 3 {
		t.Fatal("invalid applied list", err, after.Routes)
	}
	for _, old := range before.Routes {
		if old.ServiceID != service.ID && !slices.ContainsFunc(after.Routes, func(r dataplane.Route) bool {
			old.AppliedRoute = r.AppliedRoute
			return reflect.DeepEqual(r, old)
		}) {
			t.Fatal("neighbor assignment changed")
		}
	}
	model.calls = nil
	if got := run(); got != "healthy" || slices.Contains(model.calls, "commit") {
		t.Fatal("repeated edit without a change", got, model.calls)
	}
	service.CIDRs = []string{"203.0.113.0/24"}
	edited = httptest.NewRecorder()
	a.customServiceItem(edited, autonomyRequest(http.MethodPut, "/api/v1/custom-services/"+service.ID, service))
	if edited.Code != http.StatusOK {
		t.Fatal(edited.Code, edited.Body)
	}
	review(true)
	if got := run(); got != "capability-refused" || slices.Contains(model.calls, "commit") {
		t.Fatal("new mixed list inherited previous domain coverage", got, model.calls)
	}
}
