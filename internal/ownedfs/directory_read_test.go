package ownedfs

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestReadDirKeepsOriginalRootAndBound(t *testing.T) {
	base := t.TempDir()
	path := filepath.Join(base, "owned")
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(path, "original"), []byte("held"), 0600); err != nil {
		t.Fatal(err)
	}
	r, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if err := os.Rename(path, filepath.Join(base, "old")); err != nil {
		if runtime.GOOS != "windows" {
			t.Fatal(err)
		}
		t.Log("Windows prevents renaming an open root; replacement is tested on Linux")
	} else {
		if err := os.Mkdir(path, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(path, "foreign"), nil, 0600); err != nil {
			t.Fatal(err)
		}
	}
	entries, err := r.ReadDir(1)
	if err != nil || len(entries) != 1 || entries[0].Name() != "original" {
		t.Fatal("read followed replacement or ignored bound", err)
	}
	entries, err = r.ReadDir(2)
	if err != nil && !errors.Is(err, io.EOF) || len(entries) != 1 || entries[0].Name() != "original" {
		t.Fatal("read failed to restart at original directory", err)
	}
	for _, limit := range []int{-1, 0, 1025} {
		if _, err := r.ReadDir(limit); err == nil {
			t.Fatal("unbounded read accepted", limit)
		}
	}
	if f, err := r.OpenFile(".", os.O_RDONLY, 0); err == nil {
		f.Close()
		t.Fatal("ordinary open root prohibition changed")
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := r.ReadDir(1); err == nil {
		t.Fatal("closed root was reopened")
	}
}

func TestReadDirAtBoundedRealDescendant(t *testing.T) {
	path := t.TempDir()
	if err := os.Mkdir(filepath.Join(path, "child"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(path, "child/file"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	root, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	entries, err := root.ReadDirAt("child", 2)
	if err != nil || len(entries) != 1 || entries[0].Name() != "file" {
		t.Fatal(entries, err)
	}
	for _, name := range []string{".", "..", "child/file", "missing"} {
		if _, err := root.ReadDirAt(name, 2); err == nil {
			t.Fatal("non-directory accepted", name)
		}
	}
	if _, err := root.ReadDirAt("child", 0); err == nil {
		t.Fatal("unbounded read accepted")
	}
	if err := os.Symlink(filepath.Join(path, "child"), filepath.Join(path, "alias")); err == nil {
		if _, err := root.ReadDirAt("alias", 2); err == nil {
			t.Fatal("link accepted")
		}
	}
}

func TestReadDirAtKeepsOriginalRootAfterReplacement(t *testing.T) {
	base := t.TempDir()
	path := filepath.Join(base, "owned")
	if err := os.MkdirAll(filepath.Join(path, "child"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(path, "child/original"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	root, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if err := os.Rename(path, filepath.Join(base, "old")); err != nil {
		if runtime.GOOS == "windows" {
			t.Skip("Windows prevents replacing open root")
		}
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(path, "child"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(path, "child/foreign"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	entries, err := root.ReadDirAt("child", 2)
	if err != nil || len(entries) != 1 || entries[0].Name() != "original" {
		t.Fatal("descendant followed replacement root", entries, err)
	}
}
