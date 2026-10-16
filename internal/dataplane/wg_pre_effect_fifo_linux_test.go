//go:build linux

package dataplane

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// This is a private test child, with modeled kernel/tool/process leaves. The
// subprocess deadline contains the regression if a pathname open blocks on a
// writerless FIFO; no native WG process or network command is executed.
func TestWGPreEffectWriterlessFIFORefusesWithoutBlocking(t *testing.T) {
	const childKey = "RAZVILKA_WG_PRE_EFFECT_FIFO_TEST_CHILD"
	if kind := os.Getenv(childKey); kind != "" {
		m, o, ctx, cleanup, _ := wgPreEffectPendingFixture(t, true)
		wgPreEffectModelProcesses(o, false)
		s := o.scope
		path := filepath.Join(s.wgSnapshot.root, "snapshot.json")
		if kind == "runtime" {
			path = s.wgOwner.adapter.StateRoot
		} else if kind != "snapshot" {
			t.Fatal("unsupported private test child")
		}
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err := syscall.Mkfifo(path, 0600); err != nil {
			t.Fatal(err)
		}
		if err := m.JoinPendingManagedWG(ctx, cleanup); err == nil || !m.HasPendingManagedWG() || s.wgCleanupJoined {
			t.Fatal("FIFO substitution released original cleanup owner", err)
		}
		return
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"snapshot", "runtime"} {
		t.Run(kind, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, exe, "-test.run=^TestWGPreEffectWriterlessFIFORefusesWithoutBlocking$", "-test.count=1")
			cmd.Env = append(os.Environ(), childKey+"="+kind)
			if output, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("bounded private FIFO refusal failed: %v; %s", err, output)
			}
		})
	}
}
