package nativeaccept

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/ArtixSx/razvilka/internal/ownedfs"
	"github.com/ArtixSx/razvilka/internal/routeidentity"
)

func assetFixture(t *testing.T) (Request, []byte) {
	t.Helper()
	base := t.TempDir()
	data := []byte(testPrivate)
	r := Request{Binary: filepath.Join(base, "usque"), BinarySHA256: routeidentity.Hash([]byte("TEST-ONLY-INERT-NONEXECUTED-BINARY")),
		Account: filepath.Join(base, "account.json"), AccountSHA256: routeidentity.Hash(data), WorkParent: filepath.Join(base, "private")}
	if err := os.WriteFile(r.Binary, []byte("TEST-ONLY-INERT-NONEXECUTED-BINARY"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(r.Account, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(r.WorkParent, 0o700); err != nil {
		t.Fatal(err)
	}
	return r, data
}

func TestAssetsPinnedExecutableAndCancellation(t *testing.T) {
	r, _ := assetFixture(t)
	if runtime.GOOS == "linux" {
		if err := hashExecutable(context.Background(), r); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(r.Binary, []byte("TEST-ONLY-REPLACEMENT"), 0o700); err != nil {
			t.Fatal(err)
		}
		if hashExecutable(context.Background(), r) == nil {
			t.Fatal("changed executable accepted")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := readAccount(ctx, r); err == nil {
		t.Fatal("canceled account read accepted")
	}
}

func TestAssetsPrivateStagePreservesSourceAndOtherFiles(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("native POSIX private-mode enforcement; no live process/network")
	}
	r, data := assetFixture(t)
	account, err := loadAssets(context.Background(), r)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(account)
	stage, err := stageAssets(context.Background(), r, account)
	if err != nil {
		if stage != nil {
			_ = stage.Close()
		}
		t.Fatal(err)
	}
	defer stage.Close()
	other := filepath.Join(stage.Path(), "core-retained-log")
	if err := os.WriteFile(other, []byte("TEST-ONLY-LOG"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := stage.Verify(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := stage.RemoveSecret(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(stage.Path(), "engine.json")); !os.IsNotExist(err) {
		t.Fatal("staged secret not removed")
	}
	if _, err := os.Stat(other); err != nil {
		t.Fatal("unrelated retained file removed")
	}
	after, err := os.ReadFile(r.Account)
	if err != nil || string(after) != string(data) {
		t.Fatal("original account modified")
	}
}

// Directly assemble only the descriptor-backed owned-file fixture so these
// incarnation/cleanup regressions also run on Windows; no native mode is claimed.
func ownedStageFixture(t *testing.T) *ownedStage {
	t.Helper()
	r, data := assetFixture(t)
	parent, err := ownedfs.Open(r.WorkParent)
	if err != nil {
		t.Fatal(err)
	}
	name, err := parent.MkdirTemp(".", "test-only-")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(r.WorkParent, name)
	root, err := os.OpenRoot(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(path, "engine.json"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	s := &ownedStage{parent: parent, root: root, request: r, name: name, path: path}
	s.parentInfo, _ = os.Lstat(r.WorkParent)
	s.rootInfo, _ = os.Lstat(path)
	s.configInfo, _ = root.Stat("engine.json")
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestAssetsCleanupRefusesReplacementSecret(t *testing.T) {
	s := ownedStageFixture(t)
	if err := os.WriteFile(filepath.Join(s.Path(), "replacement"), []byte("TEST-ONLY-FOREIGN-SECRET"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := s.root.Rename("replacement", "engine.json"); err != nil {
		t.Fatal(err)
	}
	if s.RemoveSecret(context.Background()) == nil {
		t.Fatal("replacement secret removed")
	}
	actual, err := os.ReadFile(filepath.Join(s.Path(), "engine.json"))
	if err != nil || string(actual) != "TEST-ONLY-FOREIGN-SECRET" {
		t.Fatal("foreign secret changed")
	}
}

func TestAssetsCleanupRefusesReplacedRoot(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows forbids renaming an open root; covered by secret incarnation test")
	}
	s := ownedStageFixture(t)
	old := s.Path() + "-old"
	if err := os.Rename(s.Path(), old); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(s.Path(), 0o700); err != nil {
		t.Fatal(err)
	}
	foreign := filepath.Join(s.Path(), "engine.json")
	if err := os.WriteFile(foreign, []byte("TEST-ONLY-FOREIGN-ROOT"), 0o600); err != nil {
		t.Fatal(err)
	}
	if s.RemoveSecret(context.Background()) == nil {
		t.Fatal("replacement root cleaned")
	}
	actual, err := os.ReadFile(foreign)
	if err != nil || string(actual) != "TEST-ONLY-FOREIGN-ROOT" {
		t.Fatal("foreign root changed")
	}
	if _, err := os.Stat(filepath.Join(old, "engine.json")); err != nil {
		t.Fatal("original retained secret deleted")
	}
}

func TestAssetsSymlinkRejected(t *testing.T) {
	r, _ := assetFixture(t)
	link := filepath.Join(filepath.Dir(r.Binary), "usque-link")
	if err := os.Symlink(r.Binary, link); err != nil {
		t.Skip("symlink unavailable on test host")
	}
	r.Binary = link
	if hashExecutable(context.Background(), r) == nil {
		t.Fatal("symlink executable accepted")
	}
}
