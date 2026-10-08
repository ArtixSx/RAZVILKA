//go:build linux

package nativeowner

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/routeidentity"
)

func TestOwnerHeldAssetRejectsPermissionOnlyDriftInParentAndHelper(t *testing.T) {
	for _, tc := range []struct {
		name                string
		initial, changed    os.FileMode
		private, executable bool
		restored            bool
	}{
		{"private-exposure", 0o600, 0o644, true, false, false},
		{"private-exposure-restored", 0o600, 0o644, true, false, true},
		{"private-narrower-mode", 0o600, 0o400, true, false, false},
		{"executable-removed", 0o700, 0o600, false, true, false},
		{"executable-mode-changed", 0o755, 0o700, false, true, false},
		{"executable-setuid", 0o700, 0o700 | os.ModeSetuid, false, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "test-only-inert-asset")
			data := []byte("TEST-ONLY-NONEXECUTED-ASSET")
			if err := os.WriteFile(path, data, tc.initial); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(path, tc.initial); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			parent, err := openHeld(ctx, path, routeidentity.Hash(data), 1024, tc.private, tc.executable)
			if err != nil {
				t.Fatal(err)
			}
			defer parent.close()
			// Model the helper's inherited held FD review without executing one.
			fd, err := os.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			info, err := fd.Stat()
			if err != nil {
				_ = fd.Close()
				t.Fatal(err)
			}
			helper := &heldFile{file: fd, info: info, path: path, hash: parent.hash, limit: 1024, private: tc.private, executable: tc.executable}
			defer helper.close()
			if parent.current(ctx) != nil || helper.current(ctx) != nil {
				t.Fatal("original protected metadata refused")
			}
			if err := os.Chmod(path, tc.changed); err != nil {
				t.Fatal(err)
			}
			wantMode := tc.changed
			if tc.restored {
				if err := os.Chmod(path, tc.initial); err != nil {
					t.Fatal(err)
				}
				wantMode = tc.initial // ctime still records the broken original review
			}
			changed, err := os.Lstat(path)
			actualData, readErr := os.ReadFile(path)
			if err != nil || readErr != nil || !os.SameFile(changed, info) || changed.Size() != info.Size() || !changed.ModTime().Equal(info.ModTime()) || !bytes.Equal(actualData, data) || changed.Mode() != wantMode {
				t.Fatal("permission-only fixture changed inode/bytes/size/mtime or did not change mode")
			}
			for _, h := range []*heldFile{parent, helper} {
				if h.metadataCurrent(ctx) == nil || h.current(ctx) == nil {
					t.Fatal("parent/helper retained permission or metadata drift")
				}
			}
			stillChanged, err := os.Lstat(path)
			if err != nil || stillChanged.Mode() != wantMode {
				t.Fatal("review repaired changed permissions")
			}
		})
	}
}

func TestOwnerHeldAssetRejectsPrivateOrExecutableRequirementsOnInheritedSnapshot(t *testing.T) {
	for _, tc := range []struct {
		mode                os.FileMode
		private, executable bool
	}{{0o644, true, false}, {0o600, false, true}} {
		path := filepath.Join(t.TempDir(), "test-only-inert-inherited-asset")
		data := []byte("TEST-ONLY-NONEXECUTED-ASSET")
		if err := os.WriteFile(path, data, tc.mode); err != nil {
			t.Fatal(err)
		}
		fd, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		info, err := fd.Stat()
		if err != nil {
			_ = fd.Close()
			t.Fatal(err)
		}
		h := &heldFile{file: fd, info: info, path: path, hash: routeidentity.Hash(data), limit: 1024, private: tc.private, executable: tc.executable}
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		if h.metadataCurrent(ctx) == nil || h.current(ctx) == nil {
			_ = h.close()
			cancel()
			t.Fatal("helper accepted fresh same-inode snapshot without its role requirement")
		}
		_ = h.close()
		cancel()
	}
}

// Native POSIX FILESYSTEM fixtures only. No child/sockets/account/network probe
// runs, and no synthetic engine PID/passport/acceptance receipt is persisted.
func TestOwnerHeldAssetRejectsReplacementAndSameInodeRewrite(t *testing.T) {
	for _, replacement := range []bool{false, true} {
		dir := t.TempDir()
		path := filepath.Join(dir, "test-only-inert-asset")
		data := []byte("TEST-ONLY-NONEXECUTED-ASSET")
		if os.WriteFile(path, data, 0o600) != nil {
			t.Fatal("fixture write")
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		h, err := openHeld(ctx, path, routeidentity.Hash(data), 1024, true, false)
		if err != nil {
			t.Fatal(err)
		}
		defer h.close()
		if replacement {
			other := path + "-replacement"
			if os.WriteFile(other, data, 0o600) != nil || os.Rename(other, path) != nil {
				t.Fatal("replacement fixture")
			}
		} else {
			if os.WriteFile(path, []byte("TEST-ONLY-CHANGED-ASSET"), 0o600) != nil {
				t.Fatal("rewrite fixture")
			}
		}
		if h.current(ctx) == nil {
			t.Fatal("held inode/hash drift admitted")
		}
	}
}

func TestOwnerControlDescriptorRefusesClonedRootAndLock(t *testing.T) {
	for _, replaceRoot := range []bool{false, true} {
		dir := t.TempDir()
		root := filepath.Join(dir, "test-only-control")
		if os.Mkdir(root, 0o700) != nil {
			t.Fatal("mkdir")
		}
		marker := []byte("RAZVILKA control authority v1\n")
		lock := filepath.Join(root, ".control.lock")
		if os.WriteFile(lock, marker, 0o600) != nil {
			t.Fatal("marker")
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		a, err := openControlAnchors(ctx, Control{Root: root})
		if err != nil {
			t.Fatal(err)
		}
		defer a.close()
		if replaceRoot {
			if os.Rename(root, root+"-original") != nil || os.Mkdir(root, 0o700) != nil || os.WriteFile(lock, marker, 0o600) != nil {
				t.Fatal("clone root fixture")
			}
		} else {
			replacement := lock + "-replacement"
			if os.WriteFile(replacement, marker, 0o600) != nil || os.Rename(replacement, lock) != nil {
				t.Fatal("clone lock fixture")
			}
		}
		if a.current() == nil {
			t.Fatal("same marker/epoch bytes adopted replacement incarnation")
		}
	}
}

func TestOwnerNoHelperSettlementStillRequiresSecretRemoval(t *testing.T) {
	dir := t.TempDir()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	info, _ := root.Stat(".")
	r := &linuxSession{root: root, rootInfo: info, gate: make(chan struct{}, 1)}
	r.gate <- struct{}{}
	r.offer.Launch.Process.Dir = dir
	if os.WriteFile(filepath.Join(dir, "engine.json"), []byte("TEST-ONLY-PRIVATE-INERT-STAGE"), 0o600) != nil {
		t.Fatal("fixture")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if r.StopAndJoin(ctx) != nil || r.VerifySettled(ctx) != nil {
		t.Fatal("no actual helper created must settle without an adopted PID")
	}
	if r.ReleaseAssets(ctx) == nil {
		t.Fatal("staged secret released before removal")
	}
	if root.Remove("engine.json") != nil || r.ReleaseAssets(ctx) != nil {
		t.Fatal("known no-helper cleanup failed")
	}
}
