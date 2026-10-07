//go:build linux

package nativeowner

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/routeidentity"
)

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
