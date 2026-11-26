package app

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/autonomy"
	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/nodestore"
	"github.com/ArtixSx/razvilka/internal/onboarding"
)

func initialScopeWizardBody(t *testing.T, a *App, starterIDs, extraIDs []string) map[string]any {
	t.Helper()
	w := httptest.NewRecorder()
	a.autonomyAPI(w, autonomyRequest(http.MethodGet, "/api/v1/autonomy", nil))
	var snapshot struct {
		Policy  map[string]any           `json:"policy"`
		Starter onboarding.StarterReview `json:"starter"`
	}
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &snapshot) != nil {
		t.Fatal(w.Code, w.Body.String())
	}
	p := snapshot.Policy
	delete(p, "all_lan")
	delete(p, "default_sources")
	p["setup_complete"], p["enabled"], p["inherit_new_services"] = true, true, true
	off := autonomy.Window{Mode: "off", Start: "03:00", End: "05:00", Days: []int{1}}
	p["application"], p["components"] = off, off
	body := map[string]any{"expected_revision": p["revision"], "policy": p, "confirm": "SAVE_AUTONOMY", "use_network_scope": true}
	if snapshot.Starter.Eligible {
		if starterIDs == nil {
			starterIDs = []string{}
		}
		body["starter_sha256"], body["starter_service_ids"], body["initial_service_ids"] = snapshot.Starter.SHA256, starterIDs, extraIDs
	}
	return body
}

func putInitialScopeWizard(a *App, body map[string]any) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	a.autonomyAPI(w, autonomyRequest(http.MethodPut, "/api/v1/autonomy", body))
	return w
}

func TestInitialWizardPersonalSourceBeforeFirstImport(t *testing.T) {
	a := autonomyAPIFixture(t)
	nodeRoot := filepath.Join(t.TempDir(), "nodes")
	if err := os.Mkdir(nodeRoot, 0700); err != nil {
		t.Fatal(err)
	}
	nodes, err := nodestore.Open(nodeRoot)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = nodes.Close() })
	a.Nodes = nodes
	body := initialScopeWizardBody(t, a, nil, nil)
	policy := body["policy"].(map[string]any)
	sources := []string{"manual", "feed-kort0881-ru-sni"}
	policy["source_ids"] = append(slices.Clone(sources), "unknown-local-source")
	if w := putInitialScopeWizard(a, body); w.Code != http.StatusBadRequest || a.autonomyPolicy().SetupComplete {
		t.Fatalf("wizard accepted an unknown source: %d", w.Code)
	}
	policy["source_ids"] = sources
	if w := putInitialScopeWizard(a, body); w.Code != http.StatusOK {
		t.Fatal(w.Code, w.Body.String())
	}
	if got := a.autonomyPolicy(); !got.SetupComplete || !slices.Equal(got.SourceIDs, sources) {
		t.Fatalf("source selection was not saved: %+v", got.SourceIDs)
	}
	snapshot, err := nodes.Snapshot(t.Context(), time.Now())
	if err != nil || len(snapshot.Sources) != 0 || len(snapshot.Nodes) != 0 {
		t.Fatalf("expected an empty library after setup: %v", err)
	}
}

func TestInitialAutoScopeDefaultsToManagedLANAndWaitsForAuthority(t *testing.T) {
	a := autonomyAPIFixture(t)
	a.Catalog = catalog.NFQWS2Starter()
	a.Dataplane = dataplane.New(filepath.Join(t.TempDir(), "dataplane"))
	before := a.Store.Get()
	body := initialScopeWizardBody(t, a, []string{"discord"}, nil)
	if !a.autonomyPolicy().AllLAN {
		t.Fatal("fresh read did not offer the home LAN")
	}
	if mode := a.autonomyView(time.Now())["initial_scope_mode"]; mode != "all" {
		t.Fatalf("fresh view reported scope %q", mode)
	}
	if w := putInitialScopeWizard(a, body); w.Code != http.StatusOK {
		t.Fatal(w.Code, w.Body.String())
	}
	fresh := &App{Store: a.Store}
	if err := fresh.loadAutonomy(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := CheckAutonomyState(fresh.autonomy.path); err != nil {
		t.Fatal("the current compatibility reader did not recognize the saved managed scope", err)
	}
	p := fresh.autonomyPolicy()
	s := fresh.autonomy.doc.Services["discord"]
	if !p.SetupComplete || !p.Enabled || !p.AllLAN || !p.ManagedLANOnly || !s.Enabled ||
		!s.AllLAN || !s.ManagedLANOnly || s.ExpectedRoute != "auto" || len(s.Sources) != 0 || len(fresh.autonomy.doc.Services) != 1 {
		t.Fatalf("first setup lost the selected service or the managed LAN: %+v, %+v", p, s)
	}
	a.autonomyRound(context.Background(), time.Now())
	r := a.autonomy.doc.Runtime[s.ID]
	if r.State != "capability-refused" || !strings.Contains(r.Message, "Область домашней сети") || !reflect.DeepEqual(before, a.Store.Get()) {
		t.Fatalf("unverified LAN did not stay unassigned: %+v", r)
	}
	suspended := before
	suspended.Services = map[string]config.ServiceState{s.ID: {Enabled: true, Route: "auto"}}
	suspended.ServiceControl.SuspendedServices = suspended.Services
	if a.suspendedAutonomyScopeCurrent(t.Context(), suspended) {
		t.Fatal("Resume admitted a previous route without its managed network scope")
	}
	// Editing the default device list and returning to all of the LAN must
	// keep the network authority check for subsequently enrolled services.
	for _, all := range []bool{false, true} {
		current := a.autonomyPolicy()
		current.AllLAN, current.DefaultSources = all, nil
		if !all {
			current.DefaultSources = []string{"192.168.1.9/32"}
		}
		w := putInitialScopeWizard(a, map[string]any{"expected_revision": current.Revision, "policy": current, "confirm": "SAVE_AUTONOMY"})
		if saved := a.autonomyPolicy(); w.Code != http.StatusOK || saved.AllLAN != all || !saved.ManagedLANOnly {
			t.Fatalf("scope edit all=%t forgot managed LAN: %d %s", all, w.Code, w.Body.String())
		}
	}
}

func TestInitialAutoScopeRejectsMixedScopeAndNeverSelectsTargetsImplicitly(t *testing.T) {
	for _, eligible := range []bool{false, true} {
		a := autonomyAPIFixture(t)
		if !eligible {
			a.Catalog = catalog.Catalog{}
		}
		before := a.Store.Get()
		body := initialScopeWizardBody(t, a, nil, nil)
		policy := body["policy"].(map[string]any)
		policy["all_lan"] = nil
		if w := putInitialScopeWizard(a, body); w.Code != http.StatusBadRequest {
			t.Fatal("explicit scope was accepted by the scope-free first wizard", w.Code)
		}
		delete(policy, "all_lan")
		if eligible {
			delete(body, "starter_service_ids")
			if w := putInitialScopeWizard(a, body); w.Code != http.StatusBadRequest {
				t.Fatal("missing explicit starter list did not fail closed", w.Code)
			}
			body["starter_service_ids"] = []string{}
		}
		if w := putInitialScopeWizard(a, body); w.Code != http.StatusOK {
			t.Fatal(w.Code, w.Body.String())
		}
		if len(a.autonomy.doc.Services) != 0 || !reflect.DeepEqual(before, a.Store.Get()) {
			t.Fatal("empty first setup created targets or changed network policy")
		}
		body["expected_revision"] = a.autonomyPolicy().Revision
		if w := putInitialScopeWizard(a, body); w.Code != http.StatusConflict {
			t.Fatal("the first wizard overwrote a completed setup", w.Code)
		}
	}
}

func TestInitialAutoScopeLegacyWizardStillRequiresManagedLAN(t *testing.T) {
	a := autonomyAPIFixture(t)
	a.Catalog = catalog.NFQWS2Starter()
	body := initialScopeWizardBody(t, a, []string{"discord"}, nil)
	delete(body, "use_network_scope")
	body["policy"].(map[string]any)["all_lan"] = true
	if w := putInitialScopeWizard(a, body); w.Code != http.StatusOK {
		t.Fatal(w.Code, w.Body.String())
	}
	selected := a.autonomy.doc.Services["discord"]
	if !selected.Enabled || !a.autonomyPolicy().ManagedLANOnly || !selected.ManagedLANOnly || handedOverUnassigned(a.Store.Get(), selected) {
		t.Fatal("old wizard activated an all-LAN service without its network authority")
	}
}

func TestInitialAutoScopePreservesLegacyDeviceLimits(t *testing.T) {
	for _, sources := range [][]string{{}, {"192.168.1.9/32"}} {
		a := autonomyAPIFixture(t)
		legacy := autonomy.Default()
		legacy.DefaultSources = sources
		legacy.SourceIDs = []string{"feed-tiagorrg-vless"}
		if w := putInitialScopeWizard(a, map[string]any{"expected_revision": 0, "policy": legacy, "confirm": "SAVE_AUTONOMY"}); w.Code != http.StatusOK {
			t.Fatal("could not save the legacy device choice", w.Code, w.Body.String())
		}
		id := a.Catalog.Services[0].ID
		before := a.Store.Get()
		mode := "selected"
		if len(sources) == 0 {
			mode = "empty"
		}
		if current := a.autonomyView(time.Now())["initial_scope_mode"]; current != mode {
			t.Fatalf("old scope %v was shown as %q", sources, current)
		}
		if w := putInitialScopeWizard(a, initialScopeWizardBody(t, a, nil, []string{id})); w.Code != http.StatusOK {
			t.Fatal(w.Code, w.Body.String())
		}
		p, s := a.autonomyPolicy(), a.autonomy.doc.Services[id]
		if p.AllLAN || p.ManagedLANOnly || s.AllLAN || s.ManagedLANOnly || !slices.Equal(p.DefaultSources, sources) || !slices.Equal(s.Sources, sources) ||
			handedOverUnassigned(before, s) != (len(sources) > 0) || !reflect.DeepEqual(before, a.Store.Get()) {
			t.Fatalf("legacy scope %v was widened or lost: %+v, %+v", sources, p, s)
		}
		removed, _, err := a.withdrawAutonomySource(t.Context(), legacy.SourceIDs[0])
		p = a.autonomyPolicy()
		if err != nil || !removed || len(p.SourceIDs) != 0 || !slices.Equal(p.DefaultSources, sources) || p.AllLAN {
			t.Fatalf("could not revoke the source while retaining device scope %v: %v", sources, err)
		}
		if w := putInitialScopeWizard(a, map[string]any{"expected_revision": p.Revision, "policy": p, "confirm": "SAVE_AUTONOMY"}); w.Code != http.StatusOK {
			t.Fatal("ordinary save rejected the unchanged selected scope", w.Code, w.Body.String())
		}
		p = a.autonomyPolicy()
		p.DefaultSources = []string{"192.168.1.10/32"}
		if w := putInitialScopeWizard(a, map[string]any{"expected_revision": p.Revision, "policy": p, "confirm": "SAVE_AUTONOMY"}); w.Code != http.StatusOK {
			t.Fatal("explicit subsequent scope edit rejected", w.Code, w.Body.String())
		}
	}
}

func TestInitialAutoScopeDoesNotInferDefaultFromLegacyServiceScope(t *testing.T) {
	a := autonomyAPIFixture(t)
	if err := a.Store.UpdateService("previous", config.ServiceState{Enabled: true, Route: "direct", Sources: []string{"192.168.1.9/32"}}); err != nil {
		t.Fatal(err)
	}
	body := initialScopeWizardBody(t, a, nil, nil)
	before := a.Store.Get()
	if current := a.autonomyView(time.Now())["initial_scope_mode"]; current != "empty" {
		t.Fatalf("the view promised a new default despite prior restrictions: %q", current)
	}
	if w := putInitialScopeWizard(a, body); w.Code != http.StatusOK {
		t.Fatal(w.Code, w.Body.String())
	}
	p := a.autonomyPolicy()
	if p.AllLAN || len(p.DefaultSources) != 0 || !reflect.DeepEqual(before, a.Store.Get()) {
		t.Fatalf("wizard widened the legacy scope: %+v", p)
	}
}

func TestInitialAutoScopeKeepsNetworkPolicyExclusionsAndStop(t *testing.T) {
	a := autonomyAPIFixture(t)
	ctx := context.Background()
	clients := config.ClientScope{Mode: "selected_devices", SegmentIDs: []string{"Home"}, DeviceIDs: []string{"selected"},
		ExcludedDeviceIDs: []string{"outside"}, NewDevices: "base"}
	policy := &config.NetworkPolicy{Schema: 2, Revision: 1, Clients: clients,
		Traffic: config.TrafficSelection{Mode: "selected_services", Unavailable: "retain"}}
	if _, err := a.Store.ApproveDefaultRouteConsent(ctx, a.Store.Get(), policy, nil, strings.Repeat("a", 32), 1); err != nil {
		t.Fatal(err)
	}
	if err := a.Store.UpdateService("previous", config.ServiceState{Enabled: true, Route: "direct", Sources: []string{"192.168.1.9/32"}}); err != nil {
		t.Fatal(err)
	}
	if err := a.Store.ApplyDraft(); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Store.CommitServiceRuntime(true, map[string]string{"previous": "direct"}, a.Store.Get().Revision); err != nil {
		t.Fatal(err)
	}
	before := a.Store.Get()
	id := a.Catalog.Services[0].ID
	body := initialScopeWizardBody(t, a, nil, []string{id})
	if mode := a.autonomyView(time.Now())["initial_scope_mode"]; mode != "selected" {
		t.Fatalf("existing selected policy was shown as %q", mode)
	}
	body["release_safe_mode"] = true
	if w := putInitialScopeWizard(a, body); w.Code != http.StatusOK {
		t.Fatal(w.Code, w.Body.String())
	}
	s := a.autonomy.doc.Services[id]
	if !s.ManagedLANOnly || !reflect.DeepEqual(before, a.Store.Get()) || !before.ServiceControl.Stopped ||
		!reflect.DeepEqual(clients, before.NetworkPolicy.Clients) || autonomyScopeRefusal(before, s) != "" {
		t.Fatalf("wizard changed the saved scope, exclusions or Stop: %+v", before)
	}
	withoutPolicy := before
	withoutPolicy.NetworkPolicy = nil
	if autonomyScopeRefusal(withoutPolicy, s) == "" {
		t.Fatal("legacy routing could take over an unbound managed LAN")
	}
}

func TestInitialAutoScopeDoesNotOverwriteUnreadableJournal(t *testing.T) {
	a := autonomyAPIFixture(t)
	path := a.Store.AutomationStatePath() + ".autonomy.json"
	const invalid = `{"schema":`
	if err := os.WriteFile(path, []byte(invalid), 0600); err != nil {
		t.Fatal(err)
	}
	if w := putInitialScopeWizard(a, map[string]any{"use_network_scope": true}); w.Code != http.StatusServiceUnavailable {
		t.Fatal("bad existing policy was treated as fresh", w.Code)
	}
	image, err := os.ReadFile(path)
	if err != nil || string(image) != invalid {
		t.Fatal("unreadable journal was overwritten", err)
	}
}
