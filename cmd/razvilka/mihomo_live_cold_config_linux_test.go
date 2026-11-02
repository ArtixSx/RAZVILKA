//go:build linux

package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// Actual original metadata/bytes, no private writer lease or native authority.
func TestMihomoLiveColdConfigurationRejectsUnsafeAndReplacedInput(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("protected settings tests require root")
	}
	for _, mode := range []string{"none", "fifo", "symlink", "hardlink", "public", "oversize", "same-bytes-inode", "changed-bytes", "root-replaced", "closed", "canceled", "copied"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), time.Second)
			defer cancel()
			dir := filepath.Join(t.TempDir(), "config-root")
			if err := os.Mkdir(dir, 0700); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, "config.json")
			raw := []byte(`{"revision":1}`)
			if err := os.WriteFile(path, raw, 0600); err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "fifo", "symlink":
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				if mode == "fifo" {
					if err := syscall.Mkfifo(path, 0600); err != nil {
						t.Fatal(err)
					}
				} else if err := os.Symlink("other", path); err != nil {
					t.Fatal(err)
				}
			case "hardlink":
				if err := os.Link(path, filepath.Join(dir, "linked")); err != nil {
					t.Fatal(err)
				}
			case "public":
				if err := os.Chmod(path, 0644); err != nil {
					t.Fatal(err)
				}
			case "oversize":
				if err := os.Truncate(path, (4<<20)+1); err != nil {
					t.Fatal(err)
				}
			}
			started := time.Now()
			observation, err := openMihomoLiveColdConfiguration(ctx, path)
			if mode == "fifo" || mode == "symlink" || mode == "hardlink" || mode == "public" || mode == "oversize" {
				if err == nil || observation != nil {
					t.Fatal("unsafe input accepted", err)
				}
				if time.Since(started) >= time.Second {
					t.Fatal("unsafe input blocked")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer observation.Close()
			switch mode {
			case "copied":
				copy := &mihomoLiveColdConfiguration{self: observation, root: observation.root, file: observation.file, path: observation.path, name: observation.name, info: observation.info, ancestors: observation.ancestors, data: observation.data}
				if copy.Current(ctx) == nil || copy.Close() == nil {
					t.Fatal("copied settings holder borrowed or closed original descriptor")
				}
				if err := observation.Current(ctx); err != nil {
					t.Fatal("copied close damaged actual original", err)
				}
				return
			case "same-bytes-inode":
				if err := os.WriteFile(path+".replacement", raw, 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.Rename(path+".replacement", path); err != nil {
					t.Fatal(err)
				}
			case "changed-bytes":
				if err := os.WriteFile(path, []byte(`{"revision":2}`), 0600); err != nil {
					t.Fatal(err)
				}
			case "root-replaced":
				if err := os.Rename(dir, dir+".old"); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(dir, 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, raw, 0600); err != nil {
					t.Fatal(err)
				}
			case "closed":
				if err := observation.Close(); err != nil {
					t.Fatal(err)
				}
			case "canceled":
				cancel()
			}
			err = observation.Current(ctx)
			if (err == nil) != (mode == "none") {
				t.Fatal("original config comparison", mode, err)
			}
			if mode == "canceled" && !errors.Is(err, context.Canceled) {
				t.Fatal("cancellation lost", err)
			}
		})
	}
}
