//go:build linux

package cloudflareprovider

import (
	"context"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestProviderRecoveryRejectsUnsafeFilesystem(t *testing.T) {
	for _, mode := range []string{"root-symlink", "file-symlink", "fifo", "public-root", "public-file"} {
		t.Run(mode, func(t *testing.T) {
			base := t.TempDir()
			path := filepath.Join(base, "provider")
			if err := os.Mkdir(path, 0o700); err != nil {
				t.Fatal(err)
			}
			external := filepath.Join(base, "untouched")
			data := []byte("unrelated private file")
			if err := os.WriteFile(external, data, 0o600); err != nil {
				t.Fatal(err)
			}
			file := filepath.Join(path, storeFile)
			switch mode {
			case "root-symlink":
				link := filepath.Join(base, "alias")
				if err := os.Symlink(path, link); err != nil {
					t.Fatal(err)
				}
				path = link
			case "file-symlink":
				if err := os.Symlink(external, file); err != nil {
					t.Fatal(err)
				}
			case "fifo":
				if err := syscall.Mkfifo(file, 0o600); err != nil {
					t.Fatal(err)
				}
			case "public-root":
				if err := os.Chmod(path, 0o755); err != nil {
					t.Fatal(err)
				}
			case "public-file":
				if err := os.WriteFile(file, []byte(`{"schema":1,"owner":"razvilka","accounts":[]}`), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			if target, err := OpenRestoreTarget(path); err == nil {
				target.Close()
				t.Fatal("unsafe target accepted")
			}
			if store, err := OpenStore(path); err == nil {
				store.Close()
				t.Fatal("unsafe ordinary store accepted")
			}
			got, _ := os.ReadFile(external)
			if string(got) != string(data) {
				t.Fatal("external file changed")
			}
		})
	}
}

func TestProviderSnapshotFinalOpenIsNonblocking(t *testing.T) {
	s, path := privateStore(t)
	if err := syscall.Mkfifo(filepath.Join(path, storeFile), 0o600); err != nil {
		t.Fatal(err)
	}
	// Exercise the open used if a regular file is swapped for FIFO after stat.
	f, err := openSnapshotFile(s.root)
	if err != nil {
		t.Fatal(err)
	}
	info, err := f.Stat()
	f.Close()
	if err != nil || info.Mode()&os.ModeNamedPipe == 0 {
		t.Fatal("bad FIFO fixture")
	}
	if _, err := readSnapshotImage(context.Background(), s.root, storeLimit); err == nil {
		t.Fatal("FIFO readable as snapshot")
	}
}
