package app

import (
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/components"
	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/netidentity"
	"github.com/ArtixSx/razvilka/internal/operationgate"
)

func TestMihomoLiveColdPlanCannotMintStopOrHealth(t *testing.T) {
	root := t.TempDir()
	store, err := config.Load(filepath.Join(root, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	a := &App{Store: store, Dataplane: dataplane.New(filepath.Join(root, "dataplane")), Components: components.New()}
	if err = a.ConfigureMihomoProbe(netidentity.NewProcProvider()); err != nil {
		t.Fatal(err)
	}
	before := store.Get()
	plan := dataplane.Plan{SchemaVersion: dataplane.SchemaVersion, PlanID: "dp-cold-mihomo", Digest: strings.Repeat("a", 64), State: "committed", Ready: true, Revision: before.AppliedRevision, Routes: []dataplane.Route{{ServiceID: "listed", LogicalServiceID: "listed", Resolved: "mihomo:node-" + strings.Repeat("1", 64)}}}
	if err = a.Dataplane.Record(plan); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if handled, err := a.observeCommittedMihomo(ctx, plan); !handled || err == nil {
		t.Fatal("cold plan minted fresh native health", handled, err)
	}
	handled, outcome := a.executeMihomoServiceRuntime(ctx, "stop", before.Revision)
	if !handled || outcome.LiveApplied || outcome.Code == "" {
		t.Fatal("cold plan minted original Stop", handled, outcome)
	}
	if !reflect.DeepEqual(before, store.Get()) {
		t.Fatal("refused cold Stop changed config")
	}
	actual, found, err := a.Dataplane.Committed()
	if err != nil || !found || !reflect.DeepEqual(actual, plan) {
		t.Fatal("refused cold Stop rewrote committed plan", err)
	}
}

func TestMihomoLiveRetryKeepsOriginalCleanupOnStaleStore(t *testing.T) {
	store, err := config.Load(filepath.Join(t.TempDir(), "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err = store.SetSafeMode(false); err != nil {
		t.Fatal(err)
	}
	a := &App{Store: store, Dataplane: dataplane.New(filepath.Join(t.TempDir(), "dataplane")), Components: components.New()}
	if err = a.ConfigureMihomoProbe(netidentity.NewProcProvider()); err != nil {
		t.Fatal(err)
	}
	before := store.Get()
	plan := dataplane.Plan{SchemaVersion: dataplane.SchemaVersion, PlanID: "dp-retained-mihomo", Digest: strings.Repeat("a", 64), State: "committed", Ready: true, Revision: before.AppliedRevision, Routes: []dataplane.Route{{ServiceID: "listed", Resolved: "mihomo:node-" + strings.Repeat("1", 64)}}}
	if err = a.Dataplane.Record(plan); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	held, release, err := a.Operations.ExclusiveContext(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	cleanup, err := a.Operations.ReviewExclusiveCleanup(held)
	if err != nil {
		t.Fatal(err)
	}
	released := 0
	a.mihomoProbe.liveStop = &mihomoLiveStop{manager: a.Dataplane, store: store, before: &before, context: context.WithoutCancel(held), cleanup: cleanup, release: func() { released++; release() }}
	a.Operations.FenceJournal()
	if err = store.UpdateService("changed", config.ServiceState{Enabled: true, Route: "direct"}); err != nil {
		t.Fatal(err)
	}
	handled, outcome := a.executeMihomoServiceRuntime(ctx, "stop", store.Get().Revision)
	if !handled || outcome.Code != "SERVICE_CONTROL_CHANGED" || released != 0 {
		t.Fatal("stale retry released original cleanup custody", handled, outcome, released)
	}
	if err = cleanup.WithCurrent(ctx, func() error { return nil }); err != nil {
		t.Fatal("actual original cleanup lease lost", err)
	}
	if _, _, err = a.Operations.ExclusiveContext(ctx); !errors.Is(err, operationgate.ErrJournalRecovery) {
		t.Fatal("retry re-enabled forward work", err)
	}
}
