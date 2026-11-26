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
func TestNFQWSDirectPreparationFIFOReadDoesNotReopenReplacedPaths(t *testing.T) {
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"owner", "preparation", "candidate", "lock", "entry"} {
		t.Run(kind, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, binary, "-test.run=^TestNFQWSDirectPreparationFIFOChild$", "-test.timeout=10s")
			cmd.Env = append(os.Environ(), "RAZVILKA_NFQ_DIRECT_PREPARATION_FIFO_CHILD="+kind)
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("original metadata read blocked or failed: %v (deadline=%v) %s", err, ctx.Err(), out)
			}
		})
	}
}

func TestNFQWSDirectPreparationFIFOChild(t *testing.T) {
	kind := os.Getenv("RAZVILKA_NFQ_DIRECT_PREPARATION_FIFO_CHILD")
	if kind == "" {
		return
	}
	f := newPreEffectLANFixture(t)
	f.activateLANThenRefuseNFQ(t)
	var path string
	switch kind {
	case "owner":
		path = f.e.gate.ownerPath()
	case "preparation":
		path = filepath.Join(f.root, policyAdditionFile)
	case "candidate":
		path = filepath.Join(f.root, "candidate.json")
	case "lock":
		path = filepath.Join(f.root, policyAdditionLock)
	case "entry":
		path = filepath.Join(f.root, "foreign.json")
	default:
		t.Fatal("unknown child case")
	}
	if kind != "entry" {
		if err := os.Rename(path, path+".saved"); err != nil {
			t.Fatal(err)
		}
		if kind != "owner" {
			defer os.Rename(path+".saved", path)
			// The transaction listing must not count the saved original.
			if err := os.Rename(path+".saved", filepath.Join(filepath.Dir(f.root), filepath.Base(path)+".saved")); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := syscall.Mkfifo(path, 0600); err != nil {
		t.Fatal(err)
	}
	// The original writer's held descriptors are compared with the path;
	// no path is reopened for reading, so a FIFO cannot block retirement.
	started := time.Now()
	err := f.e.gate.Rollback(f.nextCycle(), f.e.plan, f.root)
	if err == nil || time.Since(started) > 2*time.Second {
		t.Fatal("FIFO replacement accepted or read was not bounded", err)
	}
	if f.reads != 0 || f.model.cleanup != 0 {
		t.Fatal("FIFO replacement reached an observer or the strict guard")
	}
}
