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

	"github.com/ArtixSx/razvilka/internal/routeidentity"
)

// A killed timeout child cannot hang the package/Manager test run even if a
// blocking-open regression returns. Its Manager/kernel/process IO is modeled.
func TestRetainedSingFIFORefusalsAreBounded(t *testing.T) {
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"plan", "forwarding", "lock", "receipt", "pid", "config", "observer-pid"} {
		t.Run(kind, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, binary, "-test.run=^TestRetainedSingFIFOChild$")
			cmd.Env = append(os.Environ(), "RAZVILKA_RETAINED_SING_FIFO_CHILD="+kind)
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("FIFO read failed or blocked: %v (deadline=%v) %s", err, ctx.Err(), out)
			}
		})
	}
}

func TestRetainedSingFIFOChild(t *testing.T) {
	kind := os.Getenv("RAZVILKA_RETAINED_SING_FIFO_CHILD")
	if kind == "" {
		return
	}
	f := newRetainedSingFixture(t)
	r := f.apply(t)
	var path string
	switch kind {
	case "plan":
		path = filepath.Join(f.m.StateRoot, "latest-plan.json")
	case "forwarding":
		path = f.a.forwardingPath()
	case "lock":
		path = filepath.Join(r.roots[len(r.roots)-1].path, policyAdditionLock)
	case "receipt":
		path = f.a.engineProcess().PIDPath + routeidentity.ReceiptSuffix
	case "pid", "observer-pid":
		path = f.a.sidecarProcess().PIDPath
	case "config":
		path = f.a.sidecarConfigPath()
	default:
		t.Fatal("unknown fixture")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(path, 0600); err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	if kind == "observer-pid" {
		if _, err := retainedSingPID(f.a.sidecarProcess()); err == nil {
			t.Fatal("FIFO pid accepted")
		}
	} else {
		if err := r.Current(context.Background(), f.plan); err == nil || !r.closed {
			t.Fatal("FIFO accepted or reader revivable", err)
		}
	}
	if time.Since(started) > time.Second {
		t.Fatal("static FIFO refusal was not immediate")
	}
}
