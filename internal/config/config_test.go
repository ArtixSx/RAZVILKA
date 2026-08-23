package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestDraftApplyDiscard(t *testing.T) {
	s, err := Load(filepath.Join(t.TempDir(), "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	if s.Dirty() {
		t.Fatal("new store dirty")
	}
	if err := s.UpdateService("youtube", ServiceState{Enabled: true, Route: "nfqws2"}); err != nil {
		t.Fatal(err)
	}
	if !s.Dirty() {
		t.Fatal("expected dirty")
	}
	if err := s.ApplyDraft(); err != nil {
		t.Fatal(err)
	}
	if s.Dirty() {
		t.Fatal("apply did not clear dirty")
	}
	if err := s.UpdateService("youtube", ServiceState{Enabled: false, Route: "direct"}); err != nil {
		t.Fatal(err)
	}
	if err := s.DiscardDraft(); err != nil {
		t.Fatal(err)
	}
	got := s.Get().Services["youtube"]
	if !got.Enabled || got.Route != "nfqws2" {
		t.Fatalf("discard failed: %+v", got)
	}
}

func TestApplyDraftWithRollbackRestoresAppliedState(t *testing.T) {
	store, err := Load(filepath.Join(t.TempDir(), "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.UpdateService("youtube", ServiceState{Enabled: true, Route: "nfqws2"}); err != nil {
		t.Fatal(err)
	}
	undo, err := store.ApplyDraftWithRollback()
	if err != nil {
		t.Fatal(err)
	}
	if store.Dirty() || !store.Get().AppliedServices["youtube"].Enabled {
		t.Fatalf("draft was not committed: %+v", store.Get())
	}
	if err := undo(); err != nil {
		t.Fatal(err)
	}
	if !store.Dirty() || store.Get().AppliedServices["youtube"].Enabled {
		t.Fatalf("applied state was not restored: %+v", store.Get())
	}
}

func TestConcurrentUpdatesAreNotLost(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	s, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}

	const updates = 64
	var wg sync.WaitGroup
	errs := make(chan error, updates)
	for i := 0; i < updates; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			id := fmt.Sprintf("service-%02d", i)
			errs <- s.UpdateService(id, ServiceState{Enabled: true, Route: "direct"})
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}

	got := s.Get()
	if len(got.Services) != updates {
		t.Fatalf("services=%d, want %d", len(got.Services), updates)
	}
	if got.Revision != updates {
		t.Fatalf("revision=%d, want %d", got.Revision, updates)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var persisted Config
	if err := json.Unmarshal(b, &persisted); err != nil {
		t.Fatalf("persisted config is invalid: %v", err)
	}
	if len(persisted.Services) != updates || persisted.Revision != updates {
		t.Fatalf("persisted services=%d revision=%d", len(persisted.Services), persisted.Revision)
	}
}

func TestDeviceSourcesAreCanonicalAndIsolatedFromCallers(t *testing.T) {
	store, err := Load(filepath.Join(t.TempDir(), "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	sources := []string{"192.168.1.25", "192.168.1.16/28", "192.168.1.25/32"}
	if err := store.UpdateService("video", ServiceState{Enabled: true, Route: "warp-wg", Sources: sources}); err != nil {
		t.Fatal(err)
	}
	sources[0] = "10.0.0.1"
	got := store.Get().Services["video"].Sources
	want := []string{"192.168.1.16/28", "192.168.1.25/32"}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("sources=%v want=%v", got, want)
	}
	if err := store.UpdateService("bad", ServiceState{Sources: []string{"not-an-ip"}}); err == nil {
		t.Fatal("invalid device source was accepted")
	}
}

func TestSetSafeModePersistsAndDoesNotChangeAppliedServices(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	store, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.UpdateService("video", ServiceState{Enabled: true, Route: "direct"}); err != nil {
		t.Fatal(err)
	}
	if err := store.ApplyDraft(); err != nil {
		t.Fatal(err)
	}
	before := store.Get()
	if err := store.SetSafeMode(false); err != nil {
		t.Fatal(err)
	}
	after := store.Get()
	if after.SafeMode || after.Revision != before.Revision+1 || !after.AppliedServices["video"].Enabled {
		t.Fatalf("unexpected Safe Mode update: before=%+v after=%+v", before, after)
	}
	reloaded, err := Load(path)
	if err != nil || reloaded.Get().SafeMode {
		t.Fatalf("Safe Mode update was not persisted: err=%v config=%+v", err, reloaded.Get())
	}
}
