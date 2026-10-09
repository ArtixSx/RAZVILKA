package app

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/security"
)

// Original HTTP/Store/control/scope consent are real; physical facts come from
// the existing explicit scope model. A desired route or detached review digest
// cannot substitute for the missing original managed source/runtime producer.
func TestManagedNFQOrdinaryPlanAndApplyDoNotAdoptDesiredRouteOrReviewDTO(t *testing.T) {
	a, _, _ := listScopeFixture(t, "mac", false)
	if err := a.Store.UpdateService("listed", config.ServiceState{Enabled: true, Route: "nfqws2"}); err != nil {
		t.Fatal(err)
	}
	a.Catalog = catalog.Catalog{Services: []catalog.Service{{ID: "listed", Name: "Listed", CIDRs: []string{"203.0.113.40/32"}, ProbeURL: "https://example.com/"}}}
	sec, err := security.NewGate(componentRecoveryToken)
	if err != nil {
		t.Fatal(err)
	}
	a.Security = sec
	before := a.Store.Get()
	server := httptest.NewServer(a.Handler(http.NotFoundHandler()))
	defer server.Close()
	for _, request := range []struct {
		method, path, code string
		body               any
	}{
		{"GET", "/api/v1/plan", "NETWORK_POLICY_EXECUTOR_REQUIRED", nil},
		{"POST", "/api/v1/apply", "MANAGED_NFQWS_REVIEW_REQUIRED", map[string]any{"expected_revision": before.Revision, "reviewed_digest": "1111111111111111111111111111111111111111111111111111111111111111"}},
		{"POST", "/api/v1/apply", "MANAGED_NFQWS_REVIEW_REQUIRED", map[string]any{}},
	} {
		status, data := componentHTTP(t, server, request.method, request.path, request.body, componentRecoveryToken, server.URL)
		if status != http.StatusConflict || !bytes.Contains(data, []byte(request.code)) || bytes.Contains(data, []byte(`"live_applied":true`)) || bytes.Contains(data, []byte(`"ready":true`)) || bytes.Contains(data, []byte(`"working_routes_changed":false`)) {
			t.Fatal("normal caller adopted metadata/review", status, string(data))
		}
		if !reflect.DeepEqual(a.Store.Get(), before) || a.managedNFQList != nil || a.Operations.Snapshot().Active != 0 {
			t.Fatal("normal refusal mutated Store or created private owner")
		}
	}
}
