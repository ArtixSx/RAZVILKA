package app

import (
	"encoding/json"
	"github.com/ArtixSx/razvilka/internal/autonomy"
	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/engine"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
)

func TestEnginesHTTPUsesSharedObservedInventory(t *testing.T) {
	a, _ := privateRestoreTestApp(t)
	observed := []engine.Status{{ID: "sing-box", Installed: true, Configured: true, Running: false, RuntimeReady: true, ManagedBy: "razvilka"}, {ID: "z2k", Installed: true, Running: true, External: true}}
	reads := 0
	a.EngineInventory = func() []engine.Status { reads++; return observed }
	w := httptest.NewRecorder()
	a.Handler(http.NotFoundHandler()).ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/engines", nil))
	if w.Code != 200 {
		t.Fatalf("inventory HTTP %d", w.Code)
	}
	var got []engine.Status
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if reads != 1 || !reflect.DeepEqual(got, engine.Visible(a.engineInventorySnapshot())) {
		t.Fatal("engines bypassed shared inventory or exposed external owner")
	}
	if len(got) != 1 || got[0].Running {
		t.Fatal("installed inventory became running authority")
	}
}

func TestAutonomyCapabilitiesDistinguishImplementationFromAdmission(t *testing.T) {
	a, _ := privateRestoreTestApp(t)
	p := autonomy.Policy{Enabled: true, SetupComplete: true}
	cfg := a.Store.Get()
	cfg.SafeMode = false
	cfg.ServiceControl.Mode = "auto"
	cfg.ServiceControl.Stopped = false
	tests := []struct {
		name   string
		change func(*autonomy.Policy, *config.Config)
		reason string
	}{
		{"dataplane", func(*autonomy.Policy, *config.Config) {}, "dataplane-unavailable"},
		{"setup", func(p *autonomy.Policy, _ *config.Config) { p.SetupComplete = false }, "setup-incomplete"},
		{"policy", func(p *autonomy.Policy, _ *config.Config) { p.Enabled = false }, "policy-paused"},
		{"safe", func(_ *autonomy.Policy, c *config.Config) { c.SafeMode = true }, "safe-mode"},
		{"stop", func(_ *autonomy.Policy, c *config.Config) { c.ServiceControl.Stopped = true }, "stopped"},
		{"manual", func(_ *autonomy.Policy, c *config.Config) { c.ServiceControl.Mode = "manual" }, "manual"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			policy, state := p, cfg
			test.change(&policy, &state)
			got := a.autonomyCapabilities(policy, state, false, "")
			availability := got["availability"].(map[string]runtimeCapabilityAvailability)
			route := availability["automatic_initial_apply"]
			if route.Available == nil || *route.Available || route.Reason != test.reason || a.autonomyRouteBlockReason(policy, state) != test.reason {
				t.Fatal("capability differs from actual worker route gate")
			}
			if got["automatic_initial_apply"] != true || got["implemented"].(map[string]bool)["automatic_initial_apply"] != true || availability["component_install"].Available != nil {
				t.Fatal("implementation/current availability conflated")
			}
		})
	}
	a.Dataplane = dataplane.New(t.TempDir())
	route := a.autonomyCapabilities(p, cfg, false, "")["availability"].(map[string]runtimeCapabilityAvailability)["automatic_initial_apply"]
	if route.Available != nil || route.State != "requires-service-plan" {
		t.Fatal("registered manager incorrectly granted live readiness")
	}
	route = a.autonomyCapabilities(p, cfg, true, "journal-blocked")["availability"].(map[string]runtimeCapabilityAvailability)["automatic_initial_apply"]
	if route.Available == nil || *route.Available || route.Reason != "journal-blocked" {
		t.Fatal("recovery block lost")
	}
}
