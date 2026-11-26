package app

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/autonomy"
	"github.com/ArtixSx/razvilka/internal/engineconfig"
	"github.com/ArtixSx/razvilka/internal/warp"
)

func TestAutonomyWARPConsentIsPersistentAndDoesNotGrantHealthAuthority(t *testing.T) {
	a := autonomyAPIFixture(t)
	p := saveAutonomyFixturePolicy(t, a)
	if p.AllowInitialWARPRegistration != nil {
		t.Fatal("existing configuration acquired a new WARP choice")
	}
	root := t.TempDir()
	configs := engineconfig.New(filepath.Join(root, "stage"), filepath.Join(root, "backup"))
	configs.LiveRoot = filepath.Join(root, "live")
	a.Warp = warp.New(filepath.Join(root, "warp"), filepath.Join(root, "warp-backup"), configs)
	health := a.Warp.Health().Policy
	const service = "arbitrary-site"
	if err := a.inheritAutonomyService(context.Background(), service); err != nil {
		t.Fatal(err)
	}
	p = a.autonomyPolicy()
	a.autonomyRuntime(a.autonomyPolicy().Revision, service, autonomy.Runtime{State: "warp-consent-required", NextCheck: time.Now().Add(time.Hour)})
	a.reconciler.doc.Operations = []automationOperation{{Kind: "feeds", State: "running", NextRun: time.Now().Add(time.Hour)}}
	save := func(choice string, status int) {
		t.Helper()
		encoded, err := json.Marshal(p)
		if err != nil {
			t.Fatal(err)
		}
		var wire map[string]json.RawMessage
		if err := json.Unmarshal(encoded, &wire); err != nil {
			t.Fatal(err)
		}
		if choice == "" {
			delete(wire, "allow_initial_warp_registration")
		} else {
			wire["allow_initial_warp_registration"] = json.RawMessage(choice)
		}
		w := httptest.NewRecorder()
		a.autonomyAPI(w, autonomyRequest(http.MethodPut, "/api/v1/autonomy", map[string]any{
			"expected_revision": p.Revision, "policy": wire, "confirm": "SAVE_AUTONOMY",
		}))
		if w.Code != status {
			t.Fatalf("save WARP consent %s: %d %s", choice, w.Code, w.Body.String())
		}
		fresh := &App{Store: a.Store, Catalog: a.Catalog}
		if err := fresh.loadAutonomy(context.Background()); err != nil {
			t.Fatal(err)
		}
		p = fresh.autonomyPolicy()
		if a.Warp.Health().Policy != health {
			t.Fatal("Auto choice rewrote the independent health/recovery policy")
		}
	}
	revision := p.Revision
	save("true", http.StatusBadRequest)
	if p.Revision != revision || p.AllowInitialWARPRegistration != nil {
		t.Fatal("registration without its selected method changed authority")
	}
	p.PreferredRoutes = append(p.PreferredRoutes, "warp-wg")
	save("true", http.StatusOK)
	if p.AllowInitialWARPRegistration == nil || !*p.AllowInitialWARPRegistration || !autonomyWARPRegistrationAllowed(p, health) {
		t.Fatal("wizard permission did not authorize first registration without health flags")
	}
	waiting := a.autonomy.doc.Runtime[service]
	if waiting.State != "pending" || !waiting.NextCheck.IsZero() || !a.reconciler.autonomyWakePending {
		t.Fatal("new consent did not wake its waiting service", waiting)
	}
	a.reconciler.autonomyWakePending = false
	save("", http.StatusOK)
	if p.AllowInitialWARPRegistration == nil || !*p.AllowInitialWARPRegistration || a.reconciler.autonomyWakePending {
		t.Fatal("older client omission changed or replayed registration consent")
	}
	p.PreferredRoutes = slices.DeleteFunc(p.PreferredRoutes, func(route string) bool { return route == "warp-wg" })
	save("", http.StatusOK)
	if p.AllowInitialWARPRegistration == nil || *p.AllowInitialWARPRegistration {
		t.Fatal("removing the method did not persist its revocation")
	}
	p.PreferredRoutes = append(p.PreferredRoutes, "warp-wg")
	save("", http.StatusOK)
	if p.AllowInitialWARPRegistration == nil || *p.AllowInitialWARPRegistration {
		t.Fatal("re-adding the method revived old registration permission")
	}
	revision = p.Revision
	for _, invalid := range []string{"null", `"true"`, "1"} {
		save(invalid, http.StatusBadRequest)
		if p.Revision != revision || p.AllowInitialWARPRegistration == nil || *p.AllowInitialWARPRegistration {
			t.Fatal("invalid registration input changed the saved choice")
		}
	}
	save("true", http.StatusOK)
	save("false", http.StatusOK)
	if p.AllowInitialWARPRegistration == nil || *p.AllowInitialWARPRegistration {
		t.Fatal("explicit revocation did not survive reopening the store")
	}
}

func TestAutonomyWARPConsentPreservesLegacyAndExplicitRevocationWins(t *testing.T) {
	p := autonomy.Default()
	p.PreferredRoutes = []string{"warp-wg"}
	health := warp.HealthPolicy{Enabled: true, AcceptTOS: true, AutoPrepareInitial: true}
	if autonomyWARPRegistrationAllowed(p, health) {
		t.Fatal("an unconfigured Auto inherited unrelated health authority")
	}
	p.SetupComplete = true
	if !autonomyWARPRegistrationAllowed(p, health) {
		t.Fatal("a saved legacy first-registration choice was lost")
	}
	deny := false
	p.AllowInitialWARPRegistration = &deny
	if autonomyWARPRegistrationAllowed(p, health) {
		t.Fatal("health flags overrode the explicit Auto revocation")
	}
}
