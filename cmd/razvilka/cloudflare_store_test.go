package main

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestCloudflareStoreFollowsConfigAndPreservesExistingData(t *testing.T) {
	root := t.TempDir()
	store, err := openCloudflareStore(filepath.Join(root, "candidate.json"), "")
	if err != nil {
		t.Fatal(err)
	}
	_ = store.Close()
	path := filepath.Join(root, "cloudflare-private")
	info, err := os.Stat(path)
	if err != nil || !info.IsDir() {
		t.Fatal("private store not created beside candidate config")
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o700 {
		t.Fatal("private root permissions")
	}
	if err := os.WriteFile(filepath.Join(path, "accounts.private.json"), []byte("broken-private-snapshot"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := openCloudflareStore(filepath.Join(root, "candidate.json"), ""); err == nil {
		t.Fatal("invalid existing store accepted")
	}
	raw, _ := os.ReadFile(filepath.Join(path, "accounts.private.json"))
	if string(raw) != "broken-private-snapshot" {
		t.Fatal("existing private store overwritten")
	}
	if _, err := openCloudflareStore(filepath.Join(root, "missing", "candidate.json"), ""); err == nil {
		t.Fatal("unexpected parent directories created")
	}
}

func TestCloudflareStoreRefusesSymlinkAndPublicPermissions(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(target, link); err == nil {
		if _, err := openCloudflareStore(filepath.Join(root, "config.json"), link); err == nil {
			t.Fatal("symlink store accepted")
		}
	} else {
		t.Log("symlink creation unavailable on this host")
	}
	if runtime.GOOS != "windows" {
		if err := os.Chmod(target, 0o755); err != nil {
			t.Fatal(err)
		}
		if _, err := openCloudflareStore(filepath.Join(root, "config.json"), target); err == nil {
			t.Fatal("public store accepted")
		}
		info, _ := os.Stat(target)
		if info.Mode().Perm() != 0o755 {
			t.Fatal("existing permissions were changed")
		}
	}
}
