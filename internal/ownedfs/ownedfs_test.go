package ownedfs

import (
	"os"
	"path/filepath"
	"testing"
)

func TestMutationsStayInsideOwnedRoot(t *testing.T) {
	path := t.TempDir()
	r, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	for _, name := range []string{"", ".", "..", filepath.Join("..", "outside"), path} {
		if r.RemoveAll(name) == nil || r.WriteAtomic(name, []byte("bad"), 0o600) == nil {
			t.Fatalf("unsafe target accepted: %q", name)
		}
	}
	if err := r.MkdirAll("candidates", 0o700); err != nil {
		t.Fatal(err)
	}
	name, err := r.MkdirTemp("candidates", "probe-")
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(name, "config.json")
	for _, value := range []string{"first", "second"} {
		if err := r.WriteAtomic(file, []byte(value), 0o600); err != nil {
			t.Fatal(err)
		}
		data, err := os.ReadFile(filepath.Join(path, file))
		if err != nil || string(data) != value {
			t.Fatalf("data=%q err=%v", data, err)
		}
	}
	if err := r.RemoveAll(name); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(path, name)); !os.IsNotExist(err) {
		t.Fatal("candidate remained")
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatal("owned root was removed")
	}
}

func TestSymlinksCannotRedirectRemoveOrWrite(t *testing.T) {
	path, outside := t.TempDir(), t.TempDir()
	marker := filepath.Join(outside, "keep")
	if err := os.WriteFile(marker, []byte("untouched"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(path, "link")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	r, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	for _, name := range []string{"link", filepath.Join("link", "keep")} {
		if r.RemoveAll(name) == nil || r.WriteAtomic(name, []byte("bad"), 0o600) == nil {
			t.Fatalf("symlink target accepted: %q", name)
		}
	}
	if _, err := Open(filepath.Join(path, "link")); err == nil {
		t.Fatal("symlink root accepted")
	}
	data, err := os.ReadFile(marker)
	if err != nil || string(data) != "untouched" {
		t.Fatalf("outside changed: %q %v", data, err)
	}
}

func TestRootDescriptorSurvivesPathReplacement(t *testing.T) {
	parent := t.TempDir()
	path := filepath.Join(parent, "owned")
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	r, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if err := r.MkdirAll("candidate", 0o700); err != nil {
		t.Fatal(err)
	}
	moved := filepath.Join(parent, "original")
	if err := os.Rename(path, moved); err != nil {
		t.Skipf("open directory rename unsupported: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(path, "candidate"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := r.RemoveAll("candidate"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(path, "candidate")); err != nil {
		t.Fatal("replacement was removed")
	}
	if _, err := os.Stat(filepath.Join(moved, "candidate")); !os.IsNotExist(err) {
		t.Fatal("original candidate remained")
	}
}
