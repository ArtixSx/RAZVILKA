//go:build linux

package app

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/ownedfs"
)

// A host's /opt may be shared/group-writable before RAZVILKA is installed.
// Testing the real alias opener with those modes reproduces the CI refusal
// without changing /opt or replacing ownership checks with a fake predicate.
func TestOfflineNFQWS2StopAbsentInstallationUnderSharedAlias(t *testing.T) {
	for _, mountLink := range []bool{false, true} {
		name := "directory/missing-installation"
		if mountLink {
			name = "mount-link/missing-installation"
		}
		t.Run(name, func(t *testing.T) {
			home := t.TempDir()
			volume := filepath.Join(home, "volume")
			if err := os.Mkdir(volume, 0775); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(volume, 0775); err != nil {
				t.Fatal(err)
			}
			alias := volume
			if mountLink {
				alias = filepath.Join(home, "opt")
				if err := os.Symlink(volume, alias); err != nil {
					t.Fatal(err)
				}
			}
			requested := filepath.Join(alias, "razvilka", "state", "dataplane")
			root, err := openNFQWS2HookJournalAt(requested, alias)
			if root != nil {
				root.Close()
				t.Fatal("absent installation returned an owner")
			}
			if !errors.Is(err, os.ErrNotExist) {
				t.Fatal("absent outer Stop root was mistaken for pending recovery", err)
			}
			if _, err := os.Lstat(requested); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("read-only admission created the missing root", err)
			}
		})
	}
}

func TestOfflineNFQWS2StopAbsentCheckKeepsExistingOwnerAndPathRefusals(t *testing.T) {
	for _, mode := range []string{"partial-installation", "present-root", "present-journal", "nested-dangling-symlink", "nested-symlink-to-empty-directory", "regular-parent"} {
		t.Run(mode, func(t *testing.T) {
			home := t.TempDir()
			volume := filepath.Join(home, "volume")
			if err := os.Mkdir(volume, 0775); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(volume, 0775); err != nil {
				t.Fatal(err)
			}
			alias := filepath.Join(home, "opt")
			if err := os.Symlink(volume, alias); err != nil {
				t.Fatal(err)
			}
			requested := filepath.Join(alias, "razvilka", "state", "dataplane")
			journalPath := filepath.Join(requested, dataplane.NFQWS2OfflineStopJournalName)
			var before []byte
			switch mode {
			case "partial-installation":
				if err := os.MkdirAll(filepath.Join(volume, "razvilka", "state"), 0700); err != nil {
					t.Fatal(err)
				}
			case "present-root", "present-journal":
				if err := os.MkdirAll(requested, 0700); err != nil {
					t.Fatal(err)
				}
				if mode == "present-journal" {
					before = []byte(`{"state":"pending","preserve":"original comparison evidence"}`)
					if err := os.WriteFile(journalPath, before, 0600); err != nil {
						t.Fatal(err)
					}
				}
			case "nested-dangling-symlink", "nested-symlink-to-empty-directory":
				target := filepath.Join(home, "unrelated")
				if mode == "nested-symlink-to-empty-directory" {
					if err := os.Mkdir(target, 0700); err != nil {
						t.Fatal(err)
					}
				}
				if err := os.Symlink(target, filepath.Join(volume, "razvilka")); err != nil {
					t.Fatal(err)
				}
			case "regular-parent":
				if err := os.WriteFile(filepath.Join(volume, "razvilka"), []byte("not an installation directory"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			root, err := openNFQWS2HookJournalAt(requested, alias)
			if root != nil {
				root.Close()
				t.Fatal("unsafe existing owner/path was admitted")
			}
			if err == nil || errors.Is(err, os.ErrNotExist) {
				t.Fatal("unsafe existing owner/path was mistaken for absence", err)
			}
			if before != nil {
				after, readErr := os.ReadFile(journalPath)
				if readErr != nil || !bytes.Equal(before, after) {
					t.Fatal("refusal changed the existing journal", readErr)
				}
			}
		})
	}
}

func TestOfflineNFQWS2StopAbsentInstallationBookendsOriginalAlias(t *testing.T) {
	for _, change := range []string{"none", "alias", "canonical-root", "missing-alias", "new-child"} {
		t.Run(change, func(t *testing.T) {
			home := t.TempDir()
			canonical := filepath.Join(home, "volume")
			if err := os.Mkdir(canonical, 0775); err != nil {
				t.Fatal(err)
			}
			alias := filepath.Join(home, "opt")
			if err := os.Symlink(canonical, alias); err != nil {
				t.Fatal(err)
			}
			base, err := ownedfs.Open(canonical)
			if err != nil {
				t.Fatal(err)
			}
			defer base.Close()
			if _, err := base.LstatChild("razvilka"); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("fixture is not initially absent", err)
			}
			// Replace names after the genuine first observation while retaining
			// the original descriptor, exactly the race the bookend closes.
			switch change {
			case "alias":
				other := filepath.Join(home, "other-volume")
				if err := os.MkdirAll(filepath.Join(other, "razvilka"), 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.Remove(alias); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(other, alias); err != nil {
					t.Fatal(err)
				}
			case "canonical-root":
				if err := os.Rename(canonical, canonical+"-old"); err != nil {
					t.Fatal(err)
				}
				if err := os.MkdirAll(filepath.Join(canonical, "razvilka"), 0700); err != nil {
					t.Fatal(err)
				}
			case "missing-alias":
				if err := os.Remove(alias); err != nil {
					t.Fatal(err)
				}
			case "new-child":
				if err := os.Mkdir(filepath.Join(canonical, "razvilka"), 0700); err != nil {
					t.Fatal(err)
				}
			}
			err = nfqws2HookAbsentInstallationCurrent(base, alias, canonical, "razvilka")
			if change == "none" {
				if err != nil {
					t.Fatal("unchanged original absence refused", err)
				}
			} else if !errors.Is(err, ErrNFQWS2HookRecovery) || errors.Is(err, os.ErrNotExist) {
				t.Fatal("changed installation was mistaken for absence", err)
			}
		})
	}
}
