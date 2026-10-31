package restorejournal

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestExecutableFileTargetRetainsCASAndStateDefaultMode(t *testing.T) {
	root := t.TempDir()
	binary := filepath.Join(root, "owned-binary")
	target, err := OpenExecutableFileTarget(binary)
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	before, err := target.Read(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	after := Image{Exists: true, Data: []byte("owned executable bytes")}
	if err = target.CompareAndSwap(context.Background(), before, after); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS == "linux" {
		info, err := os.Stat(binary)
		if err != nil || info.Mode().Perm() != 0755 {
			t.Fatal("executable mode lost", err)
		}
	}
	if err = target.CompareAndSwap(context.Background(), before, Image{Exists: true, Data: []byte("stale write")}); err != ErrConflict {
		t.Fatal("executable bypassed image CAS", err)
	}
	statePath := filepath.Join(root, "private-state")
	state, err := OpenFileTarget(statePath)
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	if err = state.CompareAndSwap(context.Background(), Image{}, after); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS == "linux" {
		info, err := os.Stat(statePath)
		if err != nil || info.Mode().Perm() != 0600 {
			t.Fatal("state default became executable", err)
		}
	}
}
func TestExecutableFileTargetRejectsUnknownPriorMode(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Unix executable mode contract")
	}
	path := filepath.Join(t.TempDir(), "binary")
	if err := os.WriteFile(path, []byte("prior"), 0700); err != nil {
		t.Fatal(err)
	}
	target, err := OpenExecutableFileTarget(path)
	if target != nil {
		target.Close()
	}
	if err == nil {
		t.Fatal("rollback could silently change unknown original mode")
	}
}
