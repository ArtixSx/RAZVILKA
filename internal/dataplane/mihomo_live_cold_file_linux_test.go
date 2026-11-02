//go:build linux

package dataplane

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func mihomoColdFileFixture(t *testing.T) (*os.Root, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "private")
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { root.Close() })
	return root, path
}

func TestMihomoLiveColdFileOriginalMetadataAndBounds(t *testing.T) {
	root, path := mihomoColdFileFixture(t)
	want := []byte("exact closed historical runtime bytes\n")
	name := filepath.Join(path, "config.yaml")
	if err := os.WriteFile(name, want, 0600); err != nil {
		t.Fatal(err)
	}
	before, err := root.Lstat("config.yaml")
	if err != nil {
		t.Fatal(err)
	}
	got, err := readMihomoColdFileAt(root, "config.yaml", before)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatal(got, err)
	}
	file, err := openMihomoColdFile(root, "config.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if err := os.Rename(name, name+".original"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(name, want, 0600); err != nil {
		t.Fatal(err)
	}
	if got, err := readMihomoColdFileAt(root, "config.yaml", before); err == nil || got != nil {
		t.Fatal("same bytes on a foreign inode adopted", err)
	}
	if err := os.Truncate(name, bootRetirementLimit+1); err != nil {
		t.Fatal(err)
	}
	if got, err := readMihomoColdFile(root, "config.yaml"); err == nil || got != nil {
		t.Fatal("oversize historical read accepted", err)
	}
	for _, invalid := range []string{"", ".", "../config.yaml", "runtime/../config.yaml", name} {
		if got, err := readMihomoColdFile(root, invalid); err == nil || got != nil {
			t.Fatal("unconfined name accepted", invalid)
		}
	}
}

func TestMihomoLiveColdFileNonregularSourceNeverBlocks(t *testing.T) {
	for _, kind := range []string{"fifo", "symlink", "hardlink", "public-file"} {
		t.Run(kind, func(t *testing.T) {
			root, path := mihomoColdFileFixture(t)
			name := filepath.Join(path, "runtime-file")
			switch kind {
			case "fifo":
				if err := syscall.Mkfifo(name, 0600); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				if err := os.WriteFile(filepath.Join(path, "real"), []byte("bytes"), 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink("real", name); err != nil {
					t.Fatal(err)
				}
			case "hardlink":
				if err := os.WriteFile(filepath.Join(path, "real"), []byte("bytes"), 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.Link(filepath.Join(path, "real"), name); err != nil {
					t.Fatal(err)
				}
			case "public-file":
				if err := os.WriteFile(name, []byte("not private"), 0644); err != nil {
					t.Fatal(err)
				}
			}
			type readResult struct {
				data []byte
				err  error
			}
			finished := make(chan readResult, 1)
			go func() {
				got, err := readMihomoColdFile(root, "runtime-file")
				finished <- readResult{got, err}
			}()
			select {
			case result := <-finished:
				if result.data != nil || !errors.Is(result.err, ErrMihomoLiveRetirement) {
					t.Fatal("nonregular/public source accepted", result.err)
				}
			case <-time.After(time.Second):
				t.Fatal("historical FIFO read blocked")
			}
		})
	}
}
