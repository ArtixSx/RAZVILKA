//go:build linux

package restorejournal

import (
	"context"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestFileTargetLinuxUnsafeFiles(t *testing.T) {
	for _, mode := range []string{"fifo", "symlink", "directory"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "config.json")
			outside := filepath.Join(t.TempDir(), "keep")
			if err := os.WriteFile(outside, []byte("unchanged"), 0o600); err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "fifo":
				if err := syscall.Mkfifo(path, 0o600); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				if err := os.Symlink(outside, path); err != nil {
					t.Fatal(err)
				}
			case "directory":
				if err := os.Mkdir(path, 0o700); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := ReadFileImage(context.Background(), path); err == nil {
				t.Fatal("unsafe read accepted")
			}
			if f, err := OpenFileTarget(path); err == nil {
				f.Close()
				t.Fatal("unsafe file accepted")
			}
			data, err := os.ReadFile(outside)
			if err != nil || string(data) != "unchanged" {
				t.Fatal("outside file changed")
			}
		})
	}
}

func TestFileTargetReplacementPermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte("legacy"), 0o644); err != nil {
		t.Fatal(err)
	}
	f, err := OpenFileTarget(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := f.CompareAndSwap(context.Background(), content("legacy"), content("private")); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatal("replacement is not private")
	}
}
