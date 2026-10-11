package app

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/ArtixSx/razvilka/internal/config"
)

type servicePolicyOwnershipResponse struct {
	Policy        config.ServicePolicy `json:"policy"`
	Persisted     bool                 `json:"persisted"`
	State         string               `json:"state"`
	Reason        string               `json:"reason"`
	ManagedBy     string               `json:"managed_by"`
	ManagementURL string               `json:"management_url"`
	LiveApplied   bool                 `json:"live_applied"`
}

func TestServicePolicyOwnershipPresentationGETPUT(t *testing.T) {
	cases := []struct {
		name    string
		prepare func(*testing.T, *App)
		owned   bool
		blocked bool
	}{
		{name: "unloaded"},
		{name: "loaded-unenrolled", prepare: func(t *testing.T, a *App) { saveAutonomyFixturePolicy(t, a) }},
		{name: "enrolled", prepare: enrollPolicyOwnershipFixture, owned: true},
		{name: "global-pause", owned: true, prepare: func(t *testing.T, a *App) {
			enrollPolicyOwnershipFixture(t, a)
			p := a.autonomyPolicy()
			p.Enabled = false
			w := httptest.NewRecorder()
			a.Handler(http.NotFoundHandler()).ServeHTTP(w, autonomyRequest(http.MethodPut, "/api/v1/autonomy", map[string]any{"expected_revision": p.Revision, "policy": p, "confirm": "SAVE_AUTONOMY", "release_safe_mode": false}))
			if w.Code != http.StatusOK {
				t.Fatalf("global pause: %d", w.Code)
			}
		}},
		{name: "service-pause", owned: true, prepare: func(t *testing.T, a *App) {
			saveAutonomyFixturePolicy(t, a)
			w := httptest.NewRecorder()
			a.Handler(http.NotFoundHandler()).ServeHTTP(w, autonomyRequest(http.MethodPost, "/api/v1/autonomy/services", map[string]any{"expected_revision": a.autonomyPolicy().Revision, "service_id": "telegram", "enabled": false, "use_defaults": true, "confirm": "MANAGE_SERVICE"}))
			if w.Code != http.StatusOK {
				t.Fatalf("paused enrollment: %d", w.Code)
			}
		}},
		{name: "setup-incomplete", prepare: func(t *testing.T, a *App) {
			enrollPolicyOwnershipFixture(t, a)
			a.autonomy.mu.Lock()
			a.autonomy.doc.Policy.SetupComplete = false
			a.autonomy.mu.Unlock()
		}},
		{name: "unloaded-with-membership", prepare: func(t *testing.T, a *App) {
			enrollPolicyOwnershipFixture(t, a)
			a.autonomy.mu.Lock()
			a.autonomy.loaded = false
			a.autonomy.mu.Unlock()
		}},
		// Exceptional state fixtures exercise the worker predicate directly:
		// blocked ownership applies even without loaded consent or membership.
		{name: "blocked-unloaded-without-membership", owned: true, blocked: true, prepare: func(t *testing.T, a *App) {
			a.autonomy.mu.Lock()
			a.autonomy.blocked = true
			a.autonomy.mu.Unlock()
		}},
		{name: "blocked-loaded-without-membership", owned: true, blocked: true, prepare: func(t *testing.T, a *App) {
			saveAutonomyFixturePolicy(t, a)
			a.autonomy.mu.Lock()
			a.autonomy.blocked = true
			a.autonomy.mu.Unlock()
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Actual stores, enrollment APIs and HTTP handlers; the dataplane in
			// this portable fixture is modeled and proves no native acceptance.
			a, _, _, adapter, _ := nodeAutofallbackFixture(t, 1)
			p := applyFixturePolicy(t, a)
			if tc.prepare != nil {
				tc.prepare(t, a)
			}
			before := a.Store.Get()
			legacyState, legacyReason := servicePolicyState(before, p)
			if legacyState != "ready" || a.autonomyOwnsService("telegram") != tc.owned {
				t.Fatalf("fixture admission/ownership: %s / %t", legacyState, a.autonomyOwnsService("telegram"))
			}
			autonomyBefore := policyOwnershipStateImage(t, a)
			get := readPolicyOwnershipFixture(t, a)
			assertPolicyOwnershipPresentation(t, get, tc.owned, tc.blocked, legacyState, legacyReason)
			if !get.Persisted || !reflect.DeepEqual(get.Policy, p) || !reflect.DeepEqual(a.Store.Get(), before) || !bytes.Equal(policyOwnershipStateImage(t, a), autonomyBefore) {
				t.Fatal("GET changed policy, configuration or autonomy state")
			}

			// Ownership is presentation only: ordinary manual/scenario saves
			// still use the real policy store and its revision checks.
			p.Mode = "manual"
			p.Scenario.RequireUDP = true
			body, err := json.Marshal(map[string]any{"config_revision": before.Revision, "expected_revision": p.Revision, "policy": p, "confirm": "SAVE_SERVICE_POLICY"})
			if err != nil {
				t.Fatal(err)
			}
			w := httptest.NewRecorder()
			a.Handler(http.NotFoundHandler()).ServeHTTP(w, httptest.NewRequest(http.MethodPut, "/api/v1/service-policies/telegram", bytes.NewReader(body)))
			if w.Code != http.StatusOK {
				t.Fatalf("manual/scenario save: %d", w.Code)
			}
			var put servicePolicyOwnershipResponse
			if err := json.Unmarshal(w.Body.Bytes(), &put); err != nil {
				t.Fatal(err)
			}
			after := a.Store.Get()
			saved := after.ServicePolicies["telegram"]
			legacyState, legacyReason = servicePolicyState(after, saved)
			assertPolicyOwnershipPresentation(t, put, tc.owned, tc.blocked, legacyState, legacyReason)
			if put.LiveApplied || saved.Mode != "manual" || !saved.Scenario.RequireUDP || saved.Revision != p.Revision+1 || after.Revision != before.Revision+1 || !reflect.DeepEqual(put.Policy, saved) {
				t.Fatal("manual/scenario save semantics changed")
			}
			expected := before
			expected.Revision, expected.ServicePolicies = after.Revision, after.ServicePolicies
			if !reflect.DeepEqual(after, expected) || !bytes.Equal(policyOwnershipStateImage(t, a), autonomyBefore) || len(adapter.calls) != 0 {
				t.Fatal("presentation changed routes, drafts, autonomy or dataplane")
			}
			getAfter := readPolicyOwnershipFixture(t, a)
			if getAfter.State != put.State || getAfter.Reason != put.Reason || getAfter.ManagedBy != put.ManagedBy || getAfter.ManagementURL != put.ManagementURL {
				t.Fatal("GET/PUT ownership presentation differs")
			}
			w = httptest.NewRecorder()
			a.Handler(http.NotFoundHandler()).ServeHTTP(w, httptest.NewRequest(http.MethodPut, "/api/v1/service-policies/telegram", bytes.NewReader(body)))
			if w.Code != http.StatusConflict || !reflect.DeepEqual(a.Store.Get(), after) {
				t.Fatal("ownership bypassed stale policy CAS")
			}
		})
	}
}

func enrollPolicyOwnershipFixture(t *testing.T, a *App) {
	t.Helper()
	saveAutonomyFixturePolicy(t, a)
	if err := a.inheritAutonomyService(context.Background(), "telegram"); err != nil {
		t.Fatal(err)
	}
}

func policyOwnershipStateImage(t *testing.T, a *App) []byte {
	t.Helper()
	a.autonomy.mu.Lock()
	defer a.autonomy.mu.Unlock()
	data, err := json.Marshal([]any{a.autonomy.loaded, a.autonomy.blocked, a.autonomy.doc, a.autonomy.image})
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func readPolicyOwnershipFixture(t *testing.T, a *App) servicePolicyOwnershipResponse {
	t.Helper()
	w := httptest.NewRecorder()
	a.Handler(http.NotFoundHandler()).ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/service-policies", nil))
	var response struct {
		Policies     map[string]servicePolicyOwnershipResponse `json:"policies"`
		Capabilities json.RawMessage                           `json:"capabilities"`
	}
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &response) != nil {
		t.Fatalf("policy GET: %d", w.Code)
	}
	capabilities, err := json.Marshal(servicePolicyCapabilities())
	if err != nil || !bytes.Equal(response.Capabilities, capabilities) {
		t.Fatal("legacy capabilities changed")
	}
	return response.Policies["telegram"]
}

func assertPolicyOwnershipPresentation(t *testing.T, view servicePolicyOwnershipResponse, owned, blocked bool, legacyState, legacyReason string) {
	t.Helper()
	if !owned {
		if view.State != legacyState || view.Reason != legacyReason || view.ManagedBy != "" || view.ManagementURL != "" {
			t.Fatal("unenrolled legacy presentation changed")
		}
		return
	}
	state := "managed-by-autopilot"
	if blocked {
		state = "autopilot-requires-review"
	}
	if view.State != state || view.ManagedBy != "autopilot" || view.ManagementURL != "/index.html#/managed" || !strings.Contains(view.Reason, "не выполняется") || strings.Contains(view.Reason, "Разрешены автоматическая проверка") {
		t.Fatal("owned policy advertised legacy activation")
	}
	if blocked && !strings.Contains(view.Reason, "требует проверки") {
		t.Fatal("blocked consent advertised a healthy owner")
	}
}
