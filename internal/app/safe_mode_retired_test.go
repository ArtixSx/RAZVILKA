package app

import (
	"context"
	"net/http"
	"testing"
)

// Safe Mode is retired. A flag left by an older build or by the paired offline
// restore marker (Stopped together with SafeMode) must not strand the owner:
// their own Stop/Resume clears it and then performs the requested action.
func TestServiceRuntimeClearsLeftoverSafeMode(t *testing.T) {
	a := dnsRuntimeFixture(t)
	if err := a.Store.SetSafeMode(true); err != nil {
		t.Fatal(err)
	}
	if out := a.executeServiceRuntime(context.Background(), "stop", a.Store.Get().Revision); out.Code != "" || !out.LiveApplied {
		t.Fatalf("stop with a leftover flag: %+v", out)
	}
	if cfg := a.Store.Get(); cfg.SafeMode || !cfg.ServiceControl.Stopped {
		t.Fatalf("stop kept the flag or did not stop: safe=%v stopped=%v", cfg.SafeMode, cfg.ServiceControl.Stopped)
	}
	if err := a.Store.SetSafeMode(true); err != nil {
		t.Fatal(err)
	}
	if out := a.executeServiceRuntime(context.Background(), "resume", a.Store.Get().Revision); out.Code != "" || !out.LiveApplied {
		t.Fatalf("resume after an offline-restore marker: %+v", out)
	}
	if cfg := a.Store.Get(); cfg.SafeMode || cfg.ServiceControl.Stopped || !cfg.AppliedServices["telegram"].Enabled {
		t.Fatalf("resume did not clear the marker or restore routes: safe=%v stopped=%v", cfg.SafeMode, cfg.ServiceControl.Stopped)
	}
}

// The settings endpoint can no longer enable Safe Mode; it only clears a
// leftover flag.
func TestSafeModeSettingOnlyClearsLeftoverFlag(t *testing.T) {
	a, _ := serviceControlFixture(t, 1)
	revision := a.Store.Get().Revision
	if w := controlRequest(a, "PUT", "/api/v1/settings/safe-mode", map[string]any{"enabled": true}); w.Code != http.StatusGone {
		t.Fatalf("enable answered %d %s", w.Code, w.Body.String())
	}
	if cfg := a.Store.Get(); cfg.SafeMode || cfg.Revision != revision {
		t.Fatal("refused enable changed the configuration")
	}
	if err := a.Store.SetSafeMode(true); err != nil {
		t.Fatal(err)
	}
	if w := controlRequest(a, "PUT", "/api/v1/settings/safe-mode", map[string]any{"enabled": false}); w.Code != http.StatusOK || a.Store.Get().SafeMode {
		t.Fatalf("clear answered %d %s", w.Code, w.Body.String())
	}
}
