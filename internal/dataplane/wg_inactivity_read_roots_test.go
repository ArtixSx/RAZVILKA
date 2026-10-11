package dataplane

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestWGInactivityDirectoryEnumerationRequiresOriginalHeldFD(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	var dirs [2]string
	var files [2]*os.File
	for i := range dirs {
		dirs[i] = t.TempDir()
		if err := os.Chmod(dirs[i], 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dirs[i], "same.json"), []byte("same comparison bytes"), 0600); err != nil {
			t.Fatal(err)
		}
		file, err := openWGInactivityObservationFile(dirs[i])
		if err != nil {
			t.Fatal(err)
		}
		files[i] = file
		defer file.Close()
	}
	info, err := files[0].Stat()
	if err != nil {
		t.Fatal(err)
	}
	node := wgInactivityRootNode{path: dirs[0], file: files[0], info: info}
	entries, err := wgInactivityDirectoryEntries(ctx, node)
	if err != nil || len(entries) != 1 || entries[0].Name() != "same.json" {
		t.Fatal("original directory enumeration refused", err)
	}
	// A is named and retained; the real enumerator FD is B with equal names
	// and bytes. This models A restored after opening the replacement B.
	if entries, err := wgInactivityDirectoryFDEntries(ctx, node, files[1]); err == nil || len(entries) != 0 {
		t.Fatal("foreign enumerating FD acquired original directory association")
	}
	if entries, err := wgInactivityDirectoryEntries(ctx, node); err != nil || len(entries) != 1 {
		t.Fatal("refusal changed the original directory or its offset", err)
	}
}
