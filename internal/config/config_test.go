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
