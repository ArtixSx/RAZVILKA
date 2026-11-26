//go:build linux

package restorejournal

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func foreignExistingOwner(t *testing.T, path string) {
	t.Helper()
	err := os.Chown(path, 12345, -1)
	if errors.Is(err, syscall.EINVAL) || errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EOPNOTSUPP) {
		t.Skip("environment cannot create a mapped foreign-owner fixture")
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Chown(path, os.Geteuid(), -1); err != nil {
			t.Error(err)
		}
	})
}

func TestExistingStrictOwnershipRefusesForeignActualUID(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("real foreign-owner fixture requires chown privilege")
	}
	for _, object := range []string{"file-root", "file-marker", "file-target", "journal-root", "journal-marker", "journal-receipt"} {
		t.Run(object, func(t *testing.T) {
			var target, path string
			if object == "file-root" || object == "file-marker" || object == "file-target" {
				f, config, marker := existingFileFixture(t)
				if err := f.Close(); err != nil {
					t.Fatal(err)
				}
				path = config
				target = map[string]string{"file-root": filepath.Dir(config), "file-marker": marker, "file-target": config}[object]
			} else {
				j, root, _ := existingJournalFixture(t)
				if err := j.save(j.idle()); err != nil {
					t.Fatal(err)
				}
				if err := j.Close(); err != nil {
					t.Fatal(err)
				}
				path = root
				target = map[string]string{"journal-root": root, "journal-marker": filepath.Join(root, leaseFile), "journal-receipt": filepath.Join(root, journalFile)}[object]
			}
			foreignExistingOwner(t, target)
			if object == "file-root" || object == "file-marker" || object == "file-target" {
				f, err := OpenExistingFileTarget(path)
				if f != nil || err == nil {
					if f != nil {
						_ = f.Close()
					}
					t.Fatal("foreign owned file path admitted")
				}
				if got, err := os.ReadFile(path); err != nil || string(got) != "original" {
					t.Fatal("foreign-owner refusal changed target", err)
				}
			} else {
				before, err := os.ReadFile(filepath.Join(path, journalFile))
				if err != nil {
					t.Fatal(err)
				}
				j, err := OpenExisting(path, testScope, map[string]Target{"config": idleNoTargetAccess{t}})
				if j != nil || err == nil {
					if j != nil {
						_ = j.Close()
					}
					t.Fatal("foreign owned journal path admitted")
				}
				after, err := os.ReadFile(filepath.Join(path, journalFile))
				if err != nil || !bytes.Equal(before, after) {
					t.Fatal("foreign-owner refusal changed receipt", err)
				}
			}
		})
	}
}

func TestExistingStrictOwnerChecksContinueThroughClose(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("real foreign-owner fixture requires chown privilege")
	}
	for _, object := range []string{"root", "marker", "target"} {
		t.Run(object, func(t *testing.T) {
			f, path, marker := existingFileFixture(t)
			changed := map[string]string{"root": filepath.Dir(path), "marker": marker, "target": path}[object]
			foreignExistingOwner(t, changed)
			if _, err := f.Read(context.Background()); err == nil {
				t.Fatal("changed owner admitted read")
			}
			if err := f.CompareAndSwap(context.Background(), content("original"), content("candidate")); err == nil {
				t.Fatal("changed owner admitted CAS")
			}
			if err := f.Close(); err == nil {
				t.Fatal("changed owner reported successful close")
			}
			if _, err := f.existingLease.file.Stat(); !errors.Is(err, os.ErrClosed) {
				t.Fatal("foreign-owner refusal leaked original fd", err)
			}
		})
	}
}

func TestExistingStrictRejectsHardlinkAndWritableTargetWithoutChangingLegacy(t *testing.T) {
	for _, change := range []string{"hardlink", "group-write", "legacy-readable"} {
		t.Run(change, func(t *testing.T) {
			f, path, _ := existingFileFixture(t)
			if err := f.Close(); err != nil {
				t.Fatal(err)
			}
			switch change {
			case "hardlink":
				if err := os.Link(path, path+".alias"); err != nil {
					t.Fatal(err)
				}
			case "group-write":
				if err := os.Chmod(path, 0o660); err != nil {
					t.Fatal(err)
				}
			case "legacy-readable":
				if err := os.Chmod(path, 0o644); err != nil {
					t.Fatal(err)
				}
			}
			strict, err := OpenExistingFileTarget(path)
			if change == "legacy-readable" {
				if err != nil {
					t.Fatal("strict read rejected owned legacy-readable target", err)
				}
				if err := strict.Close(); err != nil {
					t.Fatal(err)
				}
			} else if strict != nil || err == nil {
				if strict != nil {
					_ = strict.Close()
				}
				t.Fatal("unsafe target admitted")
			}
			legacy, err := OpenFileTarget(path)
			if err != nil {
				t.Fatal("ordinary open behavior changed", err)
			}
			if err := legacy.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}
