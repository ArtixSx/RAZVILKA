package engineconfig

import (
	"os"
	"path/filepath"
	"testing"
)

func isolatedLiveManager(t *testing.T) *Manager {
	t.Helper()
	root := t.TempDir()
	m := New(filepath.Join(root, "stage"), filepath.Join(root, "backups"))
	m.LiveRoot = filepath.Join(root, "live")
	return m
}

func TestLiveRootIsolatesCatalogReadsAndDraftApply(t *testing.T) {
	m, other := isolatedLiveManager(t), isolatedLiveManager(t)
	live := filepath.Join(m.LiveRoot, "opt", "etc", "razvilka", "warp", "wgcf-profile.conf")
	if err := os.MkdirAll(filepath.Dir(live), 0700); err != nil {
		t.Fatal(err)
	}
	before, after := "[Interface]\nPrivateKey = before-fixture\n", "[Interface]\nPrivateKey = after-fixture\n"
	if err := os.WriteFile(live, []byte(before), 0600); err != nil {
		t.Fatal(err)
	}
	got, err := m.ReadExpert("warp-wg", "main")
	if err != nil || got.Source != "live" || got.Path != live || got.Content != before {
		t.Fatal("instance live read mismatch", err)
	}
	missing, err := other.ReadExpert("warp-wg", "main")
	if err != nil || missing.Source != "missing" {
		t.Fatal("another instance read this instance or ambient host", err)
	}
	for _, view := range m.List() {
		for _, file := range view.Files {
			if view.ID == "warp-wg" && file.ID == "main" && (!file.Exists || file.Path != live) {
				t.Fatal("catalog escaped instance root")
			}
		}
	}
	staged, err := m.StagePrivate([]StageItem{{EngineID: "warp-wg", FileID: "main", Content: after}})
	if err != nil || len(staged) != 1 || staged[0].Path != live {
		t.Fatal("batch staging escaped instance root", err)
	}
	path, err := m.Apply("warp-wg", "main", false)
	if err != nil || path != live {
		t.Fatal("draft apply escaped instance root", err)
	}
	data, err := os.ReadFile(live)
	if err != nil || string(data) != after {
		t.Fatal("instance draft not applied", err)
	}
	backups, err := os.ReadDir(m.BackupRoot)
	if err != nil || len(backups) != 1 {
		t.Fatal("instance original not backed up", err)
	}
	data, err = os.ReadFile(filepath.Join(m.BackupRoot, backups[0].Name()))
	if err != nil || string(data) != before {
		t.Fatal("instance backup mismatch", err)
	}
}

func TestLiveRootKeepsFallbackAndGuidedReadsInsideInstance(t *testing.T) {
	m := isolatedLiveManager(t)
	alternate := filepath.Join(m.LiveRoot, "opt", "etc", "usque", "config.json")
	if err := os.MkdirAll(filepath.Dir(alternate), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(alternate, []byte(`{"fixture":"alternate"}`), 0600); err != nil {
		t.Fatal(err)
	}
	got, err := m.ReadExpert("usque", "main")
	if err != nil || got.Path != alternate || got.Source != "live" {
		t.Fatal("allowlisted fallback escaped instance", err)
	}
	view, err := m.Guided("nfqws2", "main")
	if err != nil || view.Source != "missing" {
		t.Fatal("guided editor read ambient configuration", err)
	}
	mode, err := m.NFQWSMode()
	if err != nil || mode.Source != "missing" {
		t.Fatal("mode reader read ambient configuration", err)
	}
}

func TestEmptyLiveRootPreservesFixedCatalogPaths(t *testing.T) {
	m := New(t.TempDir(), t.TempDir())
	for _, engine := range Specs() {
		for _, file := range engine.Files {
			if m.livePath(file.Paths) != choosePath(file.Paths) {
				t.Fatal("default catalog path changed")
			}
		}
	}
}
