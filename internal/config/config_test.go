package config

import (
	"path/filepath"
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
