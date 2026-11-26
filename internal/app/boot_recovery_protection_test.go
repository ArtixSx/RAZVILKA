package app

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/updatecheck"
)

func retainFailedBootRecovery(t *testing.T, a *App, state string) {
	t.Helper()
	if a.Dataplane == nil {
		a.Dataplane = dataplane.New(t.TempDir())
	}
	plan, _, err := a.Dataplane.Committed()
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(dataplane.Recovery{PlanID: plan.PlanID, State: state, Guarded: state == "safe-mode", FailureCount: 2})
	if err != nil {
		t.Fatal(err)
	}
	if state == "unreadable" {
		data = []byte("{broken")
	}
	if err := os.WriteFile(filepath.Join(a.Dataplane.StateRoot, "latest-recovery.json"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := a.Store.SetSafeMode(true); err != nil {
		t.Fatal(err)
	}
}

func TestRuntimeAndLegacySettingsCannotClearFailedBootRecovery(t *testing.T) {
	for _, state := range []string{"degraded", "safe-mode", "unreadable"} {
		t.Run(state, func(t *testing.T) {
			a := dnsRuntimeFixture(t)
			retainFailedBootRecovery(t, a, state)
			before := a.Store.Get()
			for _, action := range []string{"stop", "resume"} {
				out := a.executeServiceRuntime(context.Background(), action, before.Revision)
				if out.Code != "DATAPLANE_RECOVERY_REQUIRED" || out.LiveApplied {
					t.Fatalf("%s bypassed recovery: %+v", action, out)
				}
			}
			w := controlRequest(a, http.MethodPut, "/api/v1/settings/safe-mode", map[string]any{"enabled": false})
			if w.Code != http.StatusServiceUnavailable || !strings.Contains(w.Body.String(), "DATAPLANE_RECOVERY_REQUIRED") {
				t.Fatalf("legacy clear: %d %s", w.Code, w.Body.String())
			}
			if cfg := a.Store.Get(); !cfg.SafeMode || cfg.Revision != before.Revision {
				t.Fatal("refused action changed recovery gate or revision")
			}
			view := a.serviceControlView(context.Background())
			if view["recovery_required"] != true || view["running"] != false || view["resume_available"] != false {
				t.Fatalf("recovery was hidden: %+v", view)
			}
		})
	}
}

func TestWizardReleaseCannotClearFailedBootRecovery(t *testing.T) {
	a := autonomyAPIFixture(t)
	p := saveAutonomyFixturePolicy(t, a)
	retainFailedBootRecovery(t, a, "safe-mode")
	before := a.Store.Get()
	if a.selfUpdateNetworkQuiet() || a.selfUpdateFileAuthority(context.Background(), before.Revision) == nil {
		t.Fatal("quiet-network update bypassed recovery without a committed plan")
	}
	w := httptest.NewRecorder()
	a.autonomyAPI(w, autonomyRequest(http.MethodPut, "/api/v1/autonomy", map[string]any{"expected_revision": p.Revision, "policy": p, "confirm": "SAVE_AUTONOMY", "release_safe_mode": true}))
	if w.Code != http.StatusServiceUnavailable || !strings.Contains(w.Body.String(), "DATAPLANE_RECOVERY_REQUIRED") || !a.Store.Get().SafeMode || a.Store.Get().Revision != before.Revision {
		t.Fatalf("wizard bypassed recovery: %d %s", w.Code, w.Body.String())
	}
}

func TestHiddenRecoveryBlocksUpdateOnANoopCommittedPlan(t *testing.T) {
	a := autonomyAPIFixture(t)
	a.Dataplane = dataplane.New(t.TempDir())
	plan := dataplane.Plan{SchemaVersion: dataplane.SchemaVersion, PlanID: "dp-1111111111111111", Digest: strings.Repeat("a", 64), State: "committed", Noop: true}
	if err := a.Dataplane.Record(plan); err != nil {
		t.Fatal(err)
	}
	retainFailedBootRecovery(t, a, "safe-mode")
	if a.selfUpdateNetworkQuiet() {
		t.Fatal("guarded no-op plan called quiet")
	}
	if err := a.selfUpdateFileAuthority(context.Background(), a.Store.Get().Revision); err != updatecheck.ErrReviewChanged {
		t.Fatal("guarded no-op plan allowed update", err)
	}
}
