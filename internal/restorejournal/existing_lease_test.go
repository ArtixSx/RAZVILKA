package restorejournal

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/ArtixSx/razvilka/internal/ownedfs"
)

func existingJournalFixture(t *testing.T) (*Journal, string, map[string]Target) {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("strict original ownership requires Linux")
	}
	path := filepath.Join(t.TempDir(), "journal")
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	targets := map[string]Target{"config": idleNoTargetAccess{t}}
	initial, err := Open(path, testScope, targets)
	if err != nil {
		t.Fatal(err)
	}
	if err := initial.Close(); err != nil {
		t.Fatal(err)
	}
	j, err := OpenExisting(path, testScope, targets)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = j.Close() })
	return j, path, targets
}

func existingFileFixture(t *testing.T) (*FileTarget, string, string) {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("strict original ownership requires Linux")
	}
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	initial, err := OpenFileTarget(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := initial.Close(); err != nil {
		t.Fatal(err)
	}
	f, err := OpenExistingFileTarget(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	return f, path, filepath.Join(filepath.Dir(path), ".state-"+sum([]byte(filepath.Base(path)))+".lock")
}

func TestExistingOpenersNeverCreateMissingRootsOrMarkers(t *testing.T) {
	for _, kind := range []string{"journal", "file"} {
		for _, rootExists := range []bool{false, true} {
			t.Run(kind+map[bool]string{false: "/missing-root", true: "/missing-marker"}[rootExists], func(t *testing.T) {
				root := filepath.Join(t.TempDir(), "root")
				if rootExists {
					if err := os.Mkdir(root, 0o700); err != nil {
						t.Fatal(err)
					}
				}
				var err error
				if kind == "journal" {
					var j *Journal
					j, err = OpenExisting(root, testScope, map[string]Target{"config": idleNoTargetAccess{t}})
					if j != nil {
						_ = j.Close()
						t.Fatal("missing owner admitted")
					}
				} else {
					var f *FileTarget
					f, err = OpenExistingFileTarget(filepath.Join(root, "config.json"))
					if f != nil {
						_ = f.Close()
						t.Fatal("missing owner admitted")
					}
				}
				if err == nil {
					t.Fatal("missing owner not refused")
				}
				if !rootExists {
					if _, err := os.Stat(root); !errors.Is(err, os.ErrNotExist) {
						t.Fatal("created missing directory", err)
					}
				} else if entries, err := os.ReadDir(root); err != nil || len(entries) != 0 {
					t.Fatal("created missing marker or target", err)
				}
			})
		}
	}
}

func TestExistingJournalRetainsActualLeaseAndDoesNotCreateReceipt(t *testing.T) {
	j, path, targets := existingJournalFixture(t)
	if err := j.RequireIdle(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(path, journalFile)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("idle observation created a receipt", err)
	}
	for _, open := range []func(string, string, map[string]Target) (*Journal, error){Open, OpenExisting} {
		other, err := open(path, testScope, targets)
		if other != nil || !errors.Is(err, ErrBusy) {
			if other != nil {
				_ = other.Close()
			}
			t.Fatal("actual kernel lease was not held", err)
		}
	}
	if err := j.Close(); err != nil {
		t.Fatal(err)
	}
	next, err := OpenExisting(path, testScope, targets)
	if err != nil {
		t.Fatal("actual kernel lease was not released", err)
	}
	if err := next.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestExistingJournalRefusesPendingWithoutReplaying(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("strict original ownership requires Linux")
	}
	for _, state := range []string{"prepared", "committed"} {
		t.Run(state, func(t *testing.T) {
			initial, path, targets, list := fixture(t)
			doc := prepared(t, initial)
			doc.State = state
			if err := initial.save(doc); err != nil {
				t.Fatal(err)
			}
			if err := initial.Close(); err != nil {
				t.Fatal(err)
			}
			before, err := os.ReadFile(filepath.Join(path, journalFile))
			if err != nil {
				t.Fatal(err)
			}
			j, err := OpenExisting(path, testScope, targets)
			if err != nil {
				t.Fatal(err)
			}
			if !errors.Is(j.RequireIdle(context.Background()), ErrRecovery) {
				t.Fatal("pending journal admitted")
			}
			if err := j.Close(); err != nil {
				t.Fatal(err)
			}
			after, err := os.ReadFile(filepath.Join(path, journalFile))
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("pending receipt changed", err)
			}
			expectOld(t, list)
			for _, target := range list {
				if target.writes != 0 {
					t.Fatal("pending target was replayed")
				}
			}
		})
	}
}

func TestExistingJournalDetectsMarkerAndRootReplacementThroughClose(t *testing.T) {
	for _, change := range []string{"marker-replaced", "marker-changed", "root-replaced"} {
		t.Run(change, func(t *testing.T) {
			j, path, _ := existingJournalFixture(t)
			marker := filepath.Join(path, leaseFile)
			switch change {
			case "marker-replaced":
				if err := os.Rename(marker, marker+".retained"); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(marker, []byte(leaseMarker), 0o600); err != nil {
					t.Fatal(err)
				}
			case "marker-changed":
				bad := bytes.Repeat([]byte("x"), len(leaseMarker))
				if err := os.WriteFile(marker, bad, 0o600); err != nil {
					t.Fatal(err)
				}
			case "root-replaced":
				if err := os.Rename(path, path+".retained"); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(path, 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(marker, []byte(leaseMarker), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if !errors.Is(j.RequireIdle(context.Background()), ErrUnavailable) {
				t.Fatal("changed lifetime owner admitted")
			}
			if !errors.Is(j.Close(), ErrUnavailable) {
				t.Fatal("changed lifetime owner reported clean close")
			}
			if _, err := j.existingLease.file.Stat(); !errors.Is(err, os.ErrClosed) {
				t.Fatal("original lease descriptor leaked after refusal", err)
			}
		})
	}
}

func TestExistingFileTargetUsesRealLeaseAndExactRawCAS(t *testing.T) {
	f, path, _ := existingFileFixture(t)
	if other, err := OpenFileTarget(path); other != nil || !errors.Is(err, ErrBusy) {
		if other != nil {
			_ = other.Close()
		}
		t.Fatal("existing-only target did not hold actual file lease", err)
	}
	before, err := f.Read(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("changed-external-image"), 0o600); err != nil {
		t.Fatal(err)
	}
	if !errors.Is(f.CompareAndSwap(context.Background(), before, content("candidate")), ErrConflict) {
		t.Fatal("stale raw image admitted")
	}
	if got, err := os.ReadFile(path); err != nil || string(got) != "changed-external-image" {
		t.Fatal("conflict rewrote config", err)
	}
	current, err := f.Read(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := f.CompareAndSwap(context.Background(), current, content("candidate")); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	next, err := OpenExistingFileTarget(path)
	if err != nil {
		t.Fatal(err)
	}
	defer next.Close()
	if got, err := next.Read(context.Background()); err != nil || !equal(got, content("candidate")) {
		t.Fatal("real CAS did not publish requested image", err)
	}
}

func TestExistingFileTargetRejectsMarkerLossBeforeReadCASAndClose(t *testing.T) {
	f, path, marker := existingFileFixture(t)
	if err := os.Remove(marker); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Read(context.Background()); !errors.Is(err, ErrUnavailable) {
		t.Fatal("lost marker admitted a read", err)
	}
	if err := f.CompareAndSwap(context.Background(), content("original"), content("candidate")); !errors.Is(err, ErrUnavailable) {
		t.Fatal("lost marker admitted a write", err)
	}
	if err := f.CompareAndSwap(context.Background(), content("original"), content("original")); !errors.Is(err, ErrUnavailable) {
		t.Fatal("lost marker reported successful no-op", err)
	}
	if err := f.CompareAndSwapWithRenameAdmission(context.Background(), content("original"), content("original"), func(_ context.Context, rename func() error) error { return rename() }); !errors.Is(err, ErrUnavailable) {
		t.Fatal("lost marker reported successful admitted no-op", err)
	}
	if !errors.Is(f.Close(), ErrUnavailable) {
		t.Fatal("lost marker reported clean close")
	}
	if got, err := os.ReadFile(path); err != nil || string(got) != "original" {
		t.Fatal("lost marker changed config", err)
	}
	if _, err := os.Stat(marker); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("lost marker was recreated", err)
	}
	if _, err := f.existingLease.file.Stat(); !errors.Is(err, os.ErrClosed) {
		t.Fatal("lost marker leaked original descriptor", err)
	}
}

func TestExistingFileTargetRechecksOwnerInsideRenameAdmission(t *testing.T) {
	f, path, marker := existingFileFixture(t)
	err := f.CompareAndSwapWithRenameAdmission(context.Background(), content("original"), content("candidate"), func(_ context.Context, rename func() error) error {
		if err := os.Rename(marker, marker+".retained"); err != nil {
			return err
		}
		data, err := os.ReadFile(marker + ".retained")
		if err != nil {
			return err
		}
		if err := os.WriteFile(marker, data, 0o600); err != nil {
			return err
		}
		return rename()
	})
	if !errors.Is(err, ErrAborted) {
		t.Fatal("replaced lease reached publication", err)
	}
	if got, err := os.ReadFile(path); err != nil || string(got) != "original" {
		t.Fatal("rename admission replaced config after marker replacement", err)
	}
	if !errors.Is(f.Close(), ErrUnavailable) {
		t.Fatal("replaced lease reported clean close")
	}
}

func TestExistingOpenersPreserveMalformedMarkers(t *testing.T) {
	for _, name := range []string{leaseFile, ".state-" + sum([]byte("config.json")) + ".lock"} {
		t.Run(name, func(t *testing.T) {
			path := t.TempDir()
			if err := os.Chmod(path, 0o700); err != nil {
				t.Fatal(err)
			}
			bad := []byte("retained unknown owner")
			marker := filepath.Join(path, name)
			if err := os.WriteFile(marker, bad, 0o600); err != nil {
				t.Fatal(err)
			}
			if name == leaseFile {
				j, err := OpenExisting(path, testScope, map[string]Target{"config": idleNoTargetAccess{t}})
				if j != nil || err == nil {
					if j != nil {
						_ = j.Close()
					}
					t.Fatal("malformed journal marker admitted")
				}
			} else {
				f, err := OpenExistingFileTarget(filepath.Join(path, "config.json"))
				if f != nil || err == nil {
					if f != nil {
						_ = f.Close()
					}
					t.Fatal("malformed config marker admitted")
				}
			}
			if got, err := os.ReadFile(marker); err != nil || !bytes.Equal(got, bad) {
				t.Fatal("malformed marker was repaired", err)
			}
		})
	}
}

func TestExistingJournalLeaseKeepsInitiallyValidatedRootPermissions(t *testing.T) {
	j, path, _ := existingJournalFixture(t)
	if err := j.Close(); err != nil {
		t.Fatal(err)
	}
	validated, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o755); err != nil {
		t.Fatal(err)
	}
	root, err := ownedfs.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	lease, err := acquireExistingNamedLease(root, path, leaseFile, leaseMarker, validated)
	if lease != nil || !errors.Is(err, ErrUnavailable) {
		if lease != nil {
			_ = lease.close()
		}
		t.Fatal("later nonprivate descriptor replaced initially private root", err)
	}
	if data, err := os.ReadFile(filepath.Join(path, leaseFile)); err != nil || string(data) != leaseMarker {
		t.Fatal("permission refusal rewrote the marker", err)
	}
}
