package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/ArtixSx/razvilka/internal/config"
)

func TestRetireSafeModeClearsOnlyALeftoverFlag(t *testing.T) {
	store, err := config.Load(filepath.Join(t.TempDir(), "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	if store.Get().SafeMode {
		t.Fatal("a fresh configuration starts in Safe Mode")
	}
	revision := store.Get().Revision
	retireSafeMode(store)
	if store.Get().Revision != revision {
		t.Fatal("a configuration without the flag was rewritten")
	}
	if err := store.SetSafeMode(true); err != nil {
		t.Fatal(err)
	}
	retireSafeMode(store)
	if cfg := store.Get(); cfg.SafeMode || cfg.Revision != revision+2 {
		t.Fatalf("leftover flag not cleared once: safe=%v revision=%d", cfg.SafeMode, cfg.Revision)
	}
}

// The installer writes this file on a clean installation. It starts without
// Safe Mode and at revision 1: a stopped self-update rollback binding refuses
// revision 0, so an untouched installation must still be able to settle one.
func TestInstalledExampleConfigStartsAtRevisionOneWithoutSafeMode(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "configs", "config.example.json"))
	if err != nil {
		t.Fatal(err)
	}
	cfg, _, err := config.InspectBytes(data)
	if err != nil || cfg.SafeMode || cfg.Revision != 1 || !cleanInstallConfigUnapplied(data) {
		t.Fatalf("example config: err=%v safe=%v revision=%d", err, cfg.SafeMode, cfg.Revision)
	}
}
