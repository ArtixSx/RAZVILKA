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

// Only package-owned temporary files and modeled IO leaves exist in these
// children. Their timeout cannot kill any real router/process/resource owner.
func TestNFQWSPreEffectFIFOReadDoesNotReopenReplacedPaths(t *testing.T) {
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"snapshot", "directory"} {
		t.Run(kind, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, binary, "-test.run=^TestNFQWSPreEffectFIFOChild$", "-test.timeout=6s")
			cmd.Env = append(os.Environ(), "RAZVILKA_NFQ_PRE_EFFECT_FIFO_CHILD="+kind)
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("original read blocked or failed: %v (deadline=%v) %s", err, ctx.Err(), out)
			}
		})
	}
}

func TestNFQWSPreEffectFIFOChild(t *testing.T) {
	kind := os.Getenv("RAZVILKA_NFQ_PRE_EFFECT_FIFO_CHILD")
	if kind == "" {
		return
	}
	f := newPreEffectLANFixture(t)
	f.snapshot(t, true)
	r := f.e.preEffectLAN
	path := filepath.Join(f.root, "snapshot.json")
	if kind == "directory" {
		path = f.root
	} else if kind != "snapshot" {
		t.Fatal("unknown child case")
	}
	if err := os.Rename(path, path+".saved"); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(path, 0600); err != nil {
		t.Fatal(err)
	}
	// The replacement models the interval after opening pathname bookends.
	// The original retained reader must not reopen that pathname, and its
	// closing comparison must refuse rather than certify the old bytes.
	started := time.Now()
	var err error
	if kind == "snapshot" {
		err = r.snapshotImageCurrent()
	} else {
		err = r.onlySnapshot(true)
	}
	if err == nil || time.Since(started) > time.Second {
		t.Fatal("FIFO replacement accepted or read was not bounded", err)
	}
}
