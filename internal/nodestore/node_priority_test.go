package nodestore

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestPersonalPriorityPersistsWithoutChangingLibraryOrAdoptingNewIncarnation(t *testing.T) {
	ctx := context.Background()
	store, path := setup(t)
	now := time.Now().UTC()
	public := strings.Replace(good, "private-host.example", "public-host.example", 1)
	if _, err := store.Import(ctx, Source{ID: "feed-public", Kind: "community"}, public, now, time.Hour, false); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ImportPersonal(ctx, good, now, time.Hour, false, true); err != nil {
		t.Fatal(err)
	}
	view, err := store.SnapshotWithPriority(ctx, now)
	if err != nil || !view.PriorityChecksAvailable || len(view.Nodes) != 2 || view.Nodes[0].PriorityCheckAvailable || !view.Nodes[1].PriorityCheck {
		t.Fatalf("unexpected profile priority view: %#v, %v", view, err)
	}
	publicID, privateID := view.Nodes[0].ID, view.Nodes[1].ID
	if err := store.SetPriorityCheck(ctx, publicID, true); !errors.Is(err, ErrPriorityNotPersonal) {
		t.Fatalf("public-only priority: %v", err)
	}
	before, err := store.ExportPrivate(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SetPriorityCheck(ctx, privateID, false); err != nil {
		t.Fatal(err)
	}
	if err := store.SetPriorityCheck(ctx, privateID, true); err != nil {
		t.Fatal(err)
	}
	after, err := store.ExportPrivate(ctx)
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("scheduling metadata changed library or encrypted profile backup input", err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	view, err = store.SnapshotWithPriority(ctx, now)
	if err != nil || !view.Nodes[1].PriorityCheck {
		t.Fatal("reopening lost priority", err)
	}
	if _, err := store.Delete(ctx, privateID, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ImportPersonal(ctx, good, now.Add(2*time.Second), time.Hour, false, false); err != nil {
		t.Fatal(err)
	}
	view, err = store.SnapshotWithPriority(ctx, now.Add(3*time.Second))
	if err != nil || len(view.Nodes) != 2 || view.Nodes[1].ID != privateID || view.Nodes[1].PriorityCheck {
		t.Fatal("delete/reimport inherited the previous incarnation's priority", err)
	}
}

func TestPersonalImportStoresProfileWhenPriorityMetadataIsUnreadable(t *testing.T) {
	ctx := context.Background()
	store, path := setup(t)
	priorityPath := filepath.Join(path, priorityFile)
	if err := os.WriteFile(priorityPath, []byte("invalid-sidecar"), 0o600); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	view, err := store.ImportPersonal(ctx, good, now, time.Hour, false, true)
	if !errors.Is(err, ErrPriorityChecks) || len(view.Nodes) != 1 {
		t.Fatal("partial preference outcome concealed saved profile", err)
	}
	view, err = store.SnapshotWithPriority(ctx, now)
	if err != nil || view.PriorityChecksAvailable || len(view.Nodes) != 1 || view.Nodes[0].PriorityCheck {
		t.Fatal("unreadable priority metadata disrupted ordinary library or granted priority", err)
	}
	if data, err := os.ReadFile(priorityPath); err != nil || string(data) != "invalid-sidecar" {
		t.Fatal("unreadable metadata was overwritten", err)
	}
}
