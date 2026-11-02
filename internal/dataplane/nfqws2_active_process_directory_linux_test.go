//go:build linux

package dataplane

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/ArtixSx/razvilka/internal/restorejournal"
)

// Actual original Snapshot/root FDs and filesystem faults; source/kernel
// leaves of newPreEffectLANFixture remain models, not native Start proof.
func activeDirectoryFixture(t *testing.T) (*preEffectLANFixture, *nfqwsActiveProcessDirectory) {
	t.Helper()
	f := newPreEffectLANFixture(t)
	f.snapshot(t, false)
	d, err := holdNFQWSActiveProcessDirectory(f.ctx, f.e, f.e.preEffectLAN)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.close() })
	return f, d
}
func TestNFQWSActiveProcessDirectoryFreshManualKeepsOriginalCustody(t *testing.T) {
	f, d := activeDirectoryFixture(t)
	if err := d.current(f.ctx); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(f.e.material.adapter.StateRoot, nfqws2LeaseFile)
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("inert preparation created or adopted a process receipt", err)
	}
	target, err := restorejournal.OpenFileTarget(path)
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	if err := d.matchesTarget(f.ctx, target); err != nil {
		t.Fatal("same original parent refused", err)
	}
	other, err := restorejournal.OpenFileTarget(filepath.Join(t.TempDir(), nfqws2LeaseFile))
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	if d.matchesTarget(f.ctx, other) == nil {
		t.Fatal("foreign writer parent accepted")
	}
	if f.e.started || f.e.launchInvoked || f.e.resource != nil || f.e.material.adapter.activeProcess != nil {
		t.Fatal("directory custody manufactured native authority")
	}
	copy := &nfqwsActiveProcessDirectory{self: d, execution: d.execution, review: d.review, root: d.root, info: d.info, runtimeInfo: d.runtimeInfo}
	if copy.current(f.ctx) == nil {
		t.Fatal("copied custody accepted")
	}
	if err := d.close(); err != nil {
		t.Fatal(err)
	}
	if d.current(f.ctx) == nil {
		t.Fatal("closed custody revived")
	}
}
func TestNFQWSActiveProcessDirectoryRejectsOriginalRootReplacement(t *testing.T) {
	for _, which := range []string{"child", "runtime", "manager", "review-closed"} {
		t.Run(which, func(t *testing.T) {
			f, d := activeDirectoryFixture(t)
			path := f.e.material.adapter.StateRoot
			switch which {
			case "runtime":
				path = filepath.Dir(path)
			case "manager":
				path = f.e.material.managerRoot
			case "review-closed":
				if err := f.e.closePreEffectLAN(); err != nil {
					t.Fatal(err)
				}
			}
			if which != "review-closed" {
				if err := os.Rename(path, path+"-original"); err != nil {
					t.Fatal(err)
				}
				if err := os.MkdirAll(f.e.material.adapter.StateRoot, 0700); err != nil {
					t.Fatal(err)
				}
			}
			if d.current(f.ctx) == nil {
				t.Fatal("original directory loss accepted", which)
			}
		})
	}
}
func TestNFQWSActiveProcessDirectoryRefusesForeignLayoutWithoutRepair(t *testing.T) {
	for _, which := range []string{"public-runtime", "symlink-child", "closed-review", "canceled"} {
		t.Run(which, func(t *testing.T) {
			f := newPreEffectLANFixture(t)
			f.snapshot(t, false)
			parent := filepath.Join(f.e.material.managerRoot, "runtime")
			ctx := f.ctx
			switch which {
			case "public-runtime":
				if err := os.Mkdir(parent, 0755); err != nil {
					t.Fatal(err)
				}
			case "symlink-child":
				if err := os.Mkdir(parent, 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(t.TempDir(), f.e.material.adapter.StateRoot); err != nil {
					t.Fatal(err)
				}
			case "closed-review":
				if err := f.e.closePreEffectLAN(); err != nil {
					t.Fatal(err)
				}
			case "canceled":
				c, cancel := context.WithCancel(ctx)
				cancel()
				ctx = c
			}
			d, err := holdNFQWSActiveProcessDirectory(ctx, f.e, f.e.preEffectLAN)
			if d != nil || err == nil {
				t.Fatal("foreign layout admitted", which)
			}
			if which == "public-runtime" {
				info, err := os.Stat(parent)
				if err != nil || info.Mode().Perm() != 0755 {
					t.Fatal("foreign mode repaired", err)
				}
			}
		})
	}
}
func TestNFQWSActiveProcessDirectoryRecordedCloseFailureStaysSticky(t *testing.T) {
	f, d := activeDirectoryFixture(t)
	if err := d.close(); err != nil {
		t.Fatal(err)
	}
	// Explicit post-Close ACK-failure model. os.Root.Close itself is idempotent;
	// closing it twice is NOT a genuine syscall failure injection.
	original := errors.New("original directory close acknowledgement failed")
	d.closeErr = original
	f.e.processDirectory = d
	if !errors.Is(f.e.material.Close(), original) || !errors.Is(f.e.material.Close(), original) {
		t.Fatal("Material retirement hid a recorded original Close failure")
	}
	if d.current(f.ctx) == nil {
		t.Fatal("recorded failure revived original directory")
	}
}
