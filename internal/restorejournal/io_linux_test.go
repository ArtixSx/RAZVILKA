//go:build linux

package restorejournal

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestJournalRejectsFIFOAndSymlink(t *testing.T) {
	for _, name := range []string{leaseFile, journalFile} {
		for _, mode := range []string{"fifo", "symlink", "public-file"} {
			t.Run(name+"/"+mode, func(t *testing.T) {
				j, path, targets, _ := fixture(t)
				if err := j.Close(); err != nil {
					t.Fatal(err)
				}
				file := filepath.Join(path, name)
				if err := os.Remove(file); err != nil && !errors.Is(err, os.ErrNotExist) {
					t.Fatal(err)
				}
				switch mode {
				case "fifo":
					if err := syscall.Mkfifo(file, 0o600); err != nil {
						t.Fatal(err)
					}
				case "symlink":
					outside := filepath.Join(t.TempDir(), "outside")
					if err := os.WriteFile(outside, []byte("unchanged"), 0o600); err != nil {
						t.Fatal(err)
					}
					if err := os.Symlink(outside, file); err != nil {
						t.Fatal(err)
					}
				case "public-file":
					if err := os.WriteFile(file, []byte(leaseMarker), 0o644); err != nil {
						t.Fatal(err)
					}
					if err := os.Chmod(file, 0o644); err != nil {
						t.Fatal(err)
					}
				}
				if next, err := Open(path, testScope, targets); err == nil {
					_ = next.Close()
					t.Fatal("unsafe journal/lease accepted")
				}
			})
		}
	}
}
