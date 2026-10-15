package main

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/dataplane"
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

func TestRetiredToggleDoesNotRetireFailedBootRecoveryProtection(t *testing.T) {
	for _, tc := range []struct {
		name     string
		recovery dataplane.Recovery
		err      error
	}{
		{"degraded", dataplane.Recovery{State: "degraded", FailureCount: 1}, errors.New("adapter reconciliation failed")},
		{"boot-loop", dataplane.Recovery{State: "safe-mode", Guarded: true, FailureCount: 2}, errors.New("boot-loop guard")},
		{"unknown-error", dataplane.Recovery{}, errors.New("recovery record unreadable")},
		{"guarded-without-error", dataplane.Recovery{Guarded: true}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.json")
			store, err := config.Load(path)
			if err != nil {
				t.Fatal(err)
			}
			if err := settleRecoverySafeMode(store, tc.recovery, tc.err); err != nil {
				t.Fatal(err)
			}
			if !store.Get().SafeMode {
				t.Fatal("failed recovery reopened live writes")
			}
			reopened, err := config.Load(path)
			if err != nil || !reopened.Get().SafeMode {
				t.Fatalf("recovery gate did not persist: %v", err)
			}
			if err := settleRecoverySafeMode(store, dataplane.Recovery{State: "recovered"}, nil); err != nil {
				t.Fatal(err)
			}
			if store.Get().SafeMode {
				t.Fatal("settled successful recovery kept the retired flag")
			}
		})
	}
}

func TestNetworkStaleRecoveryDoesNotInventOrClearAProtectionFlag(t *testing.T) {
	store, err := config.Load(filepath.Join(t.TempDir(), "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, initial := range []bool{false, true} {
		if err := store.SetSafeMode(initial); err != nil {
			t.Fatal(err)
		}
		if err := settleRecoverySafeMode(store, dataplane.Recovery{State: "network-stale"}, dataplane.ErrNetworkChanged); err != nil {
			t.Fatal(err)
		}
		if store.Get().SafeMode != initial {
			t.Fatal("network-stale changed hidden recovery authority")
		}
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
