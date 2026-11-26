//go:build linux

package dataplane

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestWGInactivityDirectoryEnumerationRefusesRestoredPathAfterForeignOpen(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	base := t.TempDir()
	a, b, saved := filepath.Join(base, "a"), filepath.Join(base, "b"), filepath.Join(base, "saved-a")
	for _, path := range []string{a, b} {
		if err := os.Mkdir(path, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(path, "same.json"), []byte("same bytes"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	held, err := openWGInactivityObservationFile(a)
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	info, err := held.Stat()
	if err != nil {
		t.Fatal(err)
	}
	node := wgInactivityRootNode{path: a, file: held, info: info}
	if err := os.Rename(a, saved); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(b, a); err != nil {
		t.Fatal(err)
	}
	enumerator, err := openWGInactivityObservationFile(a)
	if err != nil {
		t.Fatal(err)
	}
	defer enumerator.Close()
	if err := os.Rename(a, b); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(saved, a); err != nil {
		t.Fatal(err)
	}
	named, err := os.Lstat(a)
	if err != nil || !os.SameFile(info, named) {
		t.Fatal("actual A incarnation was not restored", err)
	}
	if entries, err := wgInactivityDirectoryFDEntries(ctx, node, enumerator); err == nil || len(entries) != 0 {
		t.Fatal("A-to-B-to-A pathname swap hid the foreign enumerator")
	}
}
