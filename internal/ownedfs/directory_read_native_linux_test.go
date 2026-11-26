//go:build linux

package ownedfs

import (
	"path/filepath"
	"syscall"
	"testing"
)

func TestReadDirAtRejectsFIFOWithoutOpeningIt(t *testing.T) {
	path := t.TempDir()
	if err := syscall.Mkfifo(filepath.Join(path, "child"), 0600); err != nil {
		t.Fatal(err)
	}
	root, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if _, err := root.ReadDirAt("child", 2); err == nil {
		t.Fatal("FIFO admitted as descendant directory")
	}
}
