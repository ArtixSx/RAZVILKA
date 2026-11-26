package ownedfs

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestRetainedAtomicWriterKeepsOriginalReadOnlyInodeAcrossSameBytesReplacement(t *testing.T) {
	root, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	data := []byte("original journal")
	held, err := root.WriteAtomicRetained("journal", data, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	original, err := held.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := held.Write([]byte("forged")); err == nil {
		t.Fatal("retained writer descriptor is writable")
	}
	if err := root.WriteAtomic("journal", data, 0600); err != nil {
		t.Fatal(err)
	}
	replacement, err := root.Stat("journal")
	if err != nil || os.SameFile(original, replacement) {
		t.Fatal("same-byte replacement adopted original identity", err)
	}
	actual, err := io.ReadAll(held)
	if err != nil || !bytes.Equal(actual, data) {
		t.Fatal("retained original descriptor changed", err)
	}
}

func TestRetainedAtomicWriterRefusalCannotReturnDescriptorOrReplaceFile(t *testing.T) {
	dir := t.TempDir()
	root, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if err := os.Mkdir(filepath.Join(dir, "directory"), 0700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"../foreign", "directory"} {
		held, err := root.WriteAtomicRetained(name, []byte("journal"), 0600)
		if err == nil || held != nil {
			t.Fatal("refused publication returned descriptor", name, err)
		}
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 1 || entries[0].Name() != "directory" {
		t.Fatal("refusal leaked staged file", entries, err)
	}
}
