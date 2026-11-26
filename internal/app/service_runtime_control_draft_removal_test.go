package app

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/config"
)

func TestDurableStopAfterUnappliedAutonomyRemoval(t *testing.T) {
	a, _, adapter := autonomousIntegrationFixture(t)
	store, err := config.Load(filepath.Join(t.TempDir(), "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	a.Store, a.autonomy = store, autonomyState{}
	saveAutonomyFixturePolicy(t, a)
	ctx := context.Background()
	id := "my-independent-site"
	if err := store.UpdateService(id, config.ServiceState{Enabled: true, Route: "auto"}); err != nil {
		t.Fatal(err)
	}
	if err := a.inheritAutonomyService(ctx, id); err != nil {
		t.Fatal(err)
	}
	if handled, err := a.requestAutonomyRemoval(ctx, id, false); err != nil || !handled {
		t.Fatal("removal request", handled, err)
	}
	a.autonomyRound(ctx, time.Now())
	if store.Get().Services[id].Enabled || a.autonomyManaged(ctx, id) {
		t.Fatal("removal did not finish")
	}
	// Start another selection before stopping, as on the first-run panel.
	if err := store.UpdateService("telegram", config.ServiceState{Enabled: true, Route: "auto"}); err != nil {
		t.Fatal(err)
	}
	if err := a.inheritAutonomyService(ctx, "telegram"); err != nil {
		t.Fatal(err)
	}
	initReconcilerFixture(t, a, time.Now())
	stop := durableRuntimeAccept(t, a, "stop", "stop-after-draft-removal", store.Get().Revision)
	a.reconcileRound(ctx, time.Now())
	if job := durableJobAt(t, a, stop.ID); job.State != "completed" {
		t.Fatalf("Stop after draft removal: state=%s error=%s", job.State, job.RuntimeCode)
	}
	cfg := store.Get()
	if !cfg.ServiceControl.Stopped || !cfg.Services["telegram"].Enabled || cfg.AppliedRevision != 0 || len(cfg.AppliedServices) != 0 || len(adapter.calls) != 0 {
		t.Fatal("settings-only Stop changed routes or the new draft")
	}
}
