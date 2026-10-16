package ownedfs

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestRetainedAtomicWriterReportsWhetherRenameRan(t *testing.T) {
	dir := t.TempDir()
	root, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	// Refused before staging: nothing can have been published.
	if file, attempted, err := root.WriteAtomicRetainedAttempted("../escape", []byte("x"), 0600); err == nil || attempted || file != nil {
		t.Fatal("pre-staging refusal reported a rename", attempted, err)
	}
	// The rename itself fails: the destination result is the caller's unknown.
	if err := os.Mkdir(filepath.Join(dir, "busy"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "busy", "child"), []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	if file, attempted, err := root.WriteAtomicRetainedAttempted("busy", []byte("x"), 0600); err == nil || !attempted || file != nil {
		t.Fatal("failed rename not reported as attempted", attempted, err)
	}
	file, attempted, err := root.WriteAtomicRetainedAttempted("published", []byte("image"), 0600)
	if err != nil || !attempted || file == nil {
		t.Fatal("published write", attempted, err)
	}
	defer file.Close()
	data := make([]byte, 6)
	if n, _ := file.ReadAt(data, 0); !bytes.Equal(data[:n], []byte("image")) {
		t.Fatal("retained descriptor is not the published image")
	}
}

func TestRenameStaysBelowRoot(t *testing.T) {
	dir := t.TempDir()
	root, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if err := os.WriteFile(filepath.Join(dir, "a"), []byte("a"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := root.Rename("a", "../a"); err == nil {
		t.Fatal("rename escaped its root")
	}
	if err := root.Rename("a", "b"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "b")); err != nil {
		t.Fatal(err)
	}
}

func TestLinkNeverReplacesAndStaysBelowRoot(t *testing.T) {
	dir := t.TempDir()
	root, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	for name, data := range map[string]string{"a": "a", "b": "b"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := root.Link("a", "b"); err == nil {
		t.Fatal("link replaced an existing destination")
	}
	if data, _ := os.ReadFile(filepath.Join(dir, "b")); string(data) != "b" {
		t.Fatal("existing destination changed")
	}
	if err := root.Link("a", "../c"); err == nil {
		t.Fatal("link escaped its root")
	}
	if err := root.Link("a", "c"); err != nil {
		t.Fatal(err)
	}
	if data, _ := os.ReadFile(filepath.Join(dir, "c")); string(data) != "a" {
		t.Fatal("link target")
	}
}
