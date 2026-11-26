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
	"strings"
	"testing"
	"time"

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
	p.SourceIDs = []string{"feed-kort0881-ru-sni"}
	p.InheritNewServices = true
	w := httptest.NewRecorder()
	a.autonomyAPI(w, autonomyRequest("PUT", "/api/v1/autonomy", map[string]any{"expected_revision": 0, "policy": p, "confirm": "SAVE_AUTONOMY", "release_safe_mode": false}))
	if w.Code != 200 {
		t.Fatalf("policy save failed: %d %s", w.Code, w.Body.String())
	}
	return a.autonomyPolicy()
}
func TestAutonomyReviewsExactlyDisplayedDefinition(t *testing.T) {
	a := autonomyAPIFixture(t)
	saveAutonomyFixturePolicy(t, a)
	ctx := context.Background()
	service := &a.Catalog.Services[0]
	if err := a.inheritAutonomyService(ctx, service.ID); err != nil {
		t.Fatal(err)
	}
	revision := a.autonomyPolicy().Revision
	initial := a.autonomy.doc.Services[service.ID]
	service.Domains = []string{"first.example"}
	service.CIDRs = []string{"192.0.2.0/24"}
	view := func() map[string]any {
		t.Helper()
		w := httptest.NewRecorder()
		a.autonomyEnroll(w, httptest.NewRequest(http.MethodGet, "/api/v1/autonomy/services?review="+service.ID, nil))
		var result map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &result); w.Code != 200 || err != nil {
			t.Fatalf("review: %d %v", w.Code, err)
		}
		return result
	}
	post := func(confirmation string, enabled bool, rev uint64, digest any, status int) {
		t.Helper()
		w := httptest.NewRecorder()
		a.autonomyEnroll(w, autonomyRequest(http.MethodPost, "/api/v1/autonomy/services", map[string]any{
			"service_id": service.ID, "enabled": enabled, "use_defaults": true, "expected_revision": rev, "expected_definition": digest, "confirm": confirmation,
		}))
		if w.Code != status {
			t.Fatalf("%s: %d %s", confirmation, w.Code, w.Body)
		}
	}
	before := a.Store.Get()
	first := view()
	if !reflect.DeepEqual(first["domains"], []any{"first.example"}) || !reflect.DeepEqual(first["cidrs"], []any{"192.0.2.0/24"}) || first["probe_url"] != service.ProbeURL {
		t.Fatal("missing reviewed scope", first)
	}
	post("MANAGE_SERVICE", true, revision, "", 409)
	post("MANAGE_SERVICE", false, revision, "", 200)
	revision++
	if got := a.autonomy.doc.Services[service.ID]; got.Enabled || got.Definition != initial.Definition {
		t.Fatal("pause authorized scope", got)
	}
	post("MANAGE_SERVICE", true, revision, "", 409)
	post("REVIEW_SERVICE_DEFINITION", true, revision-1, first["expected_definition"], 409)
	service.Domains = []string{"second.example"}
	post("REVIEW_SERVICE_DEFINITION", true, revision, first["expected_definition"], 409)
	second := view()
	lastSwitch := time.Now().UTC().Truncate(time.Second)
	a.autonomyRuntime(revision, service.ID, autonomy.Runtime{State: "definition-changed", Switches: []time.Time{lastSwitch}, Reserves: []string{"node-" + strings.Repeat("a", 64)}})
	post("REVIEW_SERVICE_DEFINITION", true, revision, second["expected_definition"], 200)
	reloaded := &App{Store: a.Store}
	if err := reloaded.loadAutonomy(ctx); err != nil {
		t.Fatal(err)
	}
	got := reloaded.autonomy.doc.Services[service.ID]
	initial.Enabled = false
	initial.Definition = autonomyDefinition(*service)
	rt := reloaded.autonomy.doc.Runtime[service.ID]
	if !reflect.DeepEqual(got, initial) || !reflect.DeepEqual(before, a.Store.Get()) || rt.State != "pending" || len(rt.Reserves) > 0 || len(rt.Switches) != 1 || !rt.Switches[0].Equal(lastSwitch) {
		t.Fatalf("review changed unrelated state or retained evidence: %+v %+v", got, rt)
	}
	post("REVIEW_SERVICE_DEFINITION", true, revision+1, second["expected_definition"], 409)
}

func TestAutonomyAPIReadOnlyAndCAS(t *testing.T) {
	a := autonomyAPIFixture(t)
	// A leftover flag is cleared only by explicit consent, never silently.
	if err := a.Store.SetSafeMode(true); err != nil {
		t.Fatal(err)
	}
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

func TestAutonomyFirstInstallConsentPersistsSeparatelyFromUpdates(t *testing.T) {
	a := autonomyAPIFixture(t)
	p := saveAutonomyFixturePolicy(t, a)
	const id = "arbitrary-site"
	if err := a.inheritAutonomyService(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	p = a.autonomyPolicy()
	switchAt := time.Now().UTC()
	a.autonomyRuntime(a.autonomyPolicy().Revision, id, autonomy.Runtime{State: "component-window", NextCheck: switchAt.Add(time.Hour), Switches: []time.Time{switchAt}})
	p.Timezone = "Europe/Moscow"
	p.Components.Mode = "check"
	p.Components.Start = "01:00"
	p.Components.End = "02:00"
	allow, deny := true, false
	for _, choice := range []*bool{&allow, &deny, nil} {
		p.InstallMissingComponents = choice
		var policy any = p
		if choice == nil {
			policy = struct {
				autonomy.Policy
				Choice *bool `json:"install_missing_components"`
			}{Policy: p}
		}
		w := httptest.NewRecorder()
		a.autonomyAPI(w, autonomyRequest(http.MethodPut, "/api/v1/autonomy", map[string]any{
			"expected_revision": p.Revision, "policy": policy, "confirm": "SAVE_AUTONOMY",
		}))
		if w.Code != http.StatusOK {
			t.Fatalf("save first-install choice: %d %s", w.Code, w.Body.String())
		}
		if choice == &allow {
			a.autonomy.mu.Lock()
			resumed := a.autonomy.doc.Runtime[id]
			a.autonomy.mu.Unlock()
			if resumed.State != "pending" || !resumed.NextCheck.IsZero() || len(resumed.Switches) != 1 || !resumed.Switches[0].Equal(switchAt) {
				t.Fatalf("new consent did not requeue the old wait or changed its budget: %+v", resumed)
			}
		}
		fresh := &App{Store: a.Store, Catalog: a.Catalog}
		if err := fresh.loadAutonomy(context.Background()); err != nil {
			t.Fatal(err)
		}
		loaded := fresh.autonomyPolicy()
		if !reflect.DeepEqual(choice, loaded.InstallMissingComponents) || !reflect.DeepEqual(p.Components, loaded.Components) || p.Timezone != loaded.Timezone {
			t.Fatalf("reload lost consent or changed updates: %+v", loaded)
		}
		if choice != nil {
			*loaded.InstallMissingComponents = !*choice
			if again := fresh.autonomyPolicy(); !reflect.DeepEqual(choice, again.InstallMissingComponents) {
				t.Fatal("readback allowed mutation of live consent")
			}
		}
		data, err := os.ReadFile(a.Store.AutomationStatePath() + ".autonomy.json")
		if err != nil || bytes.Contains(data, []byte(`"install_missing_components"`)) != (choice != nil) {
			t.Fatalf("unexpected first-install setting in saved wire format: %v", err)
		}
		p = a.autonomyPolicy()
	}
}

func TestAutonomyFirstInstallConsentOmittedByOlderClientIsPreserved(t *testing.T) {
	for _, allowed := range []bool{false, true} {
		a := autonomyAPIFixture(t)
		p := saveAutonomyFixturePolicy(t, a)
		const service = "arbitrary-site"
		if err := a.inheritAutonomyService(context.Background(), service); err != nil {
			t.Fatal(err)
		}
		p = a.autonomyPolicy()
		save := func(policy any, confirmation string, status int) {
			t.Helper()
			w := httptest.NewRecorder()
			a.autonomyAPI(w, autonomyRequest(http.MethodPut, "/api/v1/autonomy", map[string]any{
				"expected_revision": p.Revision, "policy": policy, "confirm": confirmation,
			}))
			if w.Code != status {
				t.Fatalf("PUT with original consent %t: got %d want %d: %s", allowed, w.Code, status, w.Body.String())
			}
			p = a.autonomyPolicy()
		}
		p.InstallMissingComponents = &allowed
		save(p, "SAVE_AUTONOMY", http.StatusOK)
		retry := autonomy.Runtime{State: "component-retry", NextCheck: time.Now().UTC().Add(15 * time.Minute)}
		a.autonomyRuntime(a.autonomyPolicy().Revision, service, retry)
		priorRevision := p.Revision
		oldClient := p
		oldClient.InstallMissingComponents = nil
		oldClient.Timezone = "Europe/Moscow"
		save(oldClient, "SAVE_AUTONOMY", http.StatusOK)
		if p.InstallMissingComponents == nil || *p.InstallMissingComponents != allowed || p.Timezone != oldClient.Timezone || p.Revision != priorRevision+1 {
			t.Fatalf("field omission lost consent or did not save the other setting: %+v", p)
		}
		a.autonomy.mu.Lock()
		currentRetry := a.autonomy.doc.Runtime[service]
		a.autonomy.mu.Unlock()
		if currentRetry.State != retry.State || !currentRetry.NextCheck.Equal(retry.NextCheck) {
			t.Fatalf("field omission changed a scheduled retry: %+v", currentRetry)
		}
		priorRevision = p.Revision
		explicitNull := struct {
			autonomy.Policy
			Choice json.RawMessage `json:"install_missing_components"`
		}{Policy: oldClient, Choice: json.RawMessage(`null`)}
		save(explicitNull, "", http.StatusBadRequest)
		if p.Revision != priorRevision || p.InstallMissingComponents == nil || *p.InstallMissingComponents != allowed {
			t.Fatal("unconfirmed null changed the policy")
		}
		save(explicitNull, "SAVE_AUTONOMY", http.StatusOK)
		if p.InstallMissingComponents != nil || p.Revision != priorRevision+1 {
			t.Fatalf("confirmed explicit null did not restore legacy mode: %+v", p)
		}
	}
}

func TestAutonomyPublicNodeFailureThresholdOmittedByOlderClientIsPreserved(t *testing.T) {
	a := autonomyAPIFixture(t)
	p := saveAutonomyFixturePolicy(t, a)
	save := func(policy any, confirmation string, status, want int) {
		t.Helper()
		priorRevision := p.Revision
		w := httptest.NewRecorder()
		a.autonomyAPI(w, autonomyRequest(http.MethodPut, "/api/v1/autonomy", map[string]any{
			"expected_revision": priorRevision, "policy": policy, "confirm": confirmation,
		}))
		if w.Code != status {
			t.Fatalf("save public-node failure threshold: got %d want %d: %s", w.Code, status, w.Body.String())
		}
		if status == http.StatusOK {
			priorRevision++
		}
		fresh := &App{Store: a.Store, Catalog: a.Catalog}
		if err := fresh.loadAutonomy(context.Background()); err != nil {
			t.Fatal(err)
		}
		p = fresh.autonomyPolicy()
		if p.PublicNodeFailureThreshold != want || p.Revision != priorRevision {
			t.Fatalf("unexpected saved threshold or revision: got %d at %d, want %d at %d", p.PublicNodeFailureThreshold, p.Revision, want, priorRevision)
		}
	}
	newClient := p
	newClient.PublicNodeFailureThreshold = 7
	save(newClient, "SAVE_AUTONOMY", http.StatusOK, 7)
	oldClient := p
	oldClient.PublicNodeFailureThreshold = 0 // omitempty reproduces the older policy document.
	oldClient.Timezone = "Europe/Moscow"
	save(oldClient, "SAVE_AUTONOMY", http.StatusOK, 7)
	if p.Timezone != oldClient.Timezone {
		t.Fatal("older client could not save its setting")
	}

	for _, value := range []string{"null", "0"} {
		newClient = p
		newClient.PublicNodeFailureThreshold = 7
		save(newClient, "SAVE_AUTONOMY", http.StatusOK, 7)
		reset := struct {
			autonomy.Policy
			Threshold json.RawMessage `json:"public_node_failure_threshold"`
		}{Policy: p, Threshold: json.RawMessage(value)}
		save(reset, "", http.StatusBadRequest, 7)
		save(reset, "SAVE_AUTONOMY", http.StatusOK, 0)
		if effective := p.EffectivePublicNodeFailureThreshold(); effective != 3 {
			t.Fatalf("explicit reset did not restore the default: %d", effective)
		}
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

func TestAutonomyEnrollmentSchedulesOnlyPersistedServiceIntent(t *testing.T) {
	for _, tt := range []struct {
		name                 string
		sources              []string
		stale, replacePolicy bool
		status               int
	}{
		{name: "success", sources: []string{"192.168.1.62"}, status: http.StatusOK},
		{name: "empty-scope", status: http.StatusBadRequest},
		{name: "stale-revision", sources: []string{"192.168.1.62"}, stale: true, status: http.StatusConflict},
		{name: "failed-write", sources: []string{"192.168.1.62"}, replacePolicy: true, status: http.StatusServiceUnavailable},
	} {
		t.Run(tt.name, func(t *testing.T) {
			a := autonomyAPIFixture(t)
			p := saveAutonomyFixturePolicy(t, a)
			a.reconciler.wake = make(chan struct{}, 1)
			nextDue := time.Now().Add(time.Hour)
			a.reconciler.doc.Operations = []automationOperation{
				{Kind: "feeds", NextRun: nextDue},
				{Kind: "service-checks", NextRun: nextDue},
			}
			before := a.Store.Get()
			revision := p.Revision
			if tt.stale {
				revision--
			}
			if tt.replacePolicy {
				if err := os.WriteFile(a.autonomy.path, []byte("{}"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			w := httptest.NewRecorder()
			a.autonomyEnroll(w, autonomyRequest(http.MethodPost, "/api/v1/autonomy/services", map[string]any{
				"service_id": "arbitrary-site", "enabled": true, "sources": tt.sources,
				"expected_revision": revision, "confirm": "MANAGE_SERVICE",
			}))
			if w.Code != tt.status || !reflect.DeepEqual(before, a.Store.Get()) {
				t.Fatalf("enrollment status = %d (%s), expected %d and untouched live config", w.Code, w.Body, tt.status)
			}
			if tt.status != http.StatusOK {
				if len(a.reconciler.wake) != 0 || !a.reconciler.doc.Operations[0].NextRun.Equal(nextDue) || len(a.autonomy.doc.Services) != 0 || len(a.autonomy.doc.Runtime) != 0 || a.autonomyPolicy().Revision != p.Revision {
					t.Fatal("rejected enrollment was published or woke the router scheduler")
				}
				return
			}
			select {
			case <-a.reconciler.wake:
			default:
				t.Fatal("successful enrollment did not wake the router scheduler")
			}
			if a.reconciler.doc.Operations[0].NextRun.After(time.Now()) || !a.reconciler.doc.Operations[1].NextRun.Equal(nextDue) {
				t.Fatal("successful enrollment must only make the autonomy task due")
			}
			data, err := os.ReadFile(a.autonomy.path)
			if err != nil {
				t.Fatal(err)
			}
			persisted, err := decodeAutonomy(data)
			s := persisted.Services["arbitrary-site"]
			r := persisted.Runtime["arbitrary-site"]
			if err != nil || persisted.Policy.Revision != p.Revision+1 || !s.Enabled || s.AllLAN || !reflect.DeepEqual(s.Sources, []string{"192.168.1.62/32"}) || r.State != "pending" || !r.NextCheck.IsZero() {
				t.Fatalf("incorrect saved intent or next check: %+v, %+v, %v", s, r, err)
			}
		})
	}
}

func TestAutonomyEnrollmentPreservesOwnedRouteIntent(t *testing.T) {
	for _, tt := range []struct {
		name, draftRoute, expectedRoute string
		removing                        bool
	}{
		{name: "applied draft", draftRoute: "xray", expectedRoute: "auto"},
		{name: "manual draft change", draftRoute: "wireguard", expectedRoute: "wireguard"},
		{name: "pending removal", draftRoute: "xray", expectedRoute: "xray", removing: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			a := autonomyAPIFixture(t)
			p := saveAutonomyFixturePolicy(t, a)
			const id = "arbitrary-site"
			service, _ := a.autonomyService(id)
			draft := config.ServiceState{Enabled: true, Route: "xray", Mode: "xray", Sources: p.DefaultSources}
			a.autonomy.doc.Services[id] = autonomy.Service{ID: id, Enabled: true, Removing: tt.removing, Sources: p.DefaultSources, Definition: autonomyDefinition(service), DraftFingerprint: autonomyDraftFingerprint(draft), ExpectedRoute: "auto"}
			draft.Route, draft.Mode = tt.draftRoute, tt.draftRoute
			if err := a.Store.UpdateService(id, draft); err != nil {
				t.Fatal(err)
			}
			w := httptest.NewRecorder()
			a.autonomyEnroll(w, autonomyRequest(http.MethodPost, "/api/v1/autonomy/services", map[string]any{
				"service_id": id, "enabled": true, "all_lan": true,
				"expected_revision": p.Revision, "confirm": "MANAGE_SERVICE",
			}))
			got := a.autonomy.doc.Services[id]
			if w.Code != http.StatusOK || got.ExpectedRoute != tt.expectedRoute || !got.AllLAN || len(got.Sources) != 0 {
				t.Fatalf("incorrect scope or route intent: %d %s %+v", w.Code, w.Body, got)
			}
		})
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
			p.SourceIDs = []string{"feed-kort0881-ru-sni"}
			if what == "source" {
				p.SourceIDs = []string{"not-in-registry"}
			} else {
				p.Application.Mode = "upgrade"
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
