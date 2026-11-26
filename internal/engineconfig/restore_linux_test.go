//go:build linux

package engineconfig

import (
	"context"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestDraftTargetRejectsSymlinkFIFOAndPublicDirectories(t *testing.T) {
	for _, kind := range []string{"symlink-root", "symlink-slot", "symlink-file", "fifo", "public-root", "public-slot", "public-file"} {
		t.Run(kind, func(t *testing.T) {
			base := t.TempDir()
			stage := filepath.Join(base, "stage")
			outside := filepath.Join(base, "outside")
			if err := os.Mkdir(outside, 0o700); err != nil {
				t.Fatal(err)
			}
			secret := filepath.Join(outside, "unchanged")
			if err := os.WriteFile(secret, []byte("preserve"), 0o600); err != nil {
				t.Fatal(err)
			}
			if kind == "symlink-root" {
				if err := os.Symlink(outside, stage); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := os.Mkdir(stage, 0o700); err != nil {
					t.Fatal(err)
				}
				slot := filepath.Join(stage, "sing-box")
				if kind == "symlink-slot" {
					if err := os.Symlink(outside, slot); err != nil {
						t.Fatal(err)
					}
				} else {
					if err := os.Mkdir(slot, 0o700); err != nil {
						t.Fatal(err)
					}
					path := filepath.Join(slot, "main.draft")
					switch kind {
					case "symlink-file":
						if err := os.Symlink(secret, path); err != nil {
							t.Fatal(err)
						}
					case "fifo":
						if err := syscall.Mkfifo(path, 0o600); err != nil {
							t.Fatal(err)
						}
					case "public-root":
						if err := os.Chmod(stage, 0o755); err != nil {
							t.Fatal(err)
						}
					case "public-slot":
						if err := os.Chmod(slot, 0o755); err != nil {
							t.Fatal(err)
						}
					case "public-file":
						if err := os.WriteFile(path, []byte("{}"), 0o644); err != nil {
							t.Fatal(err)
						}
					}
				}
			}
			if target, err := OpenRestoreTarget(stage, "sing-box", "main"); err == nil {
				target.Close()
				t.Fatal("unsafe target opened")
			}
			m := New(stage, filepath.Join(base, "backup"))
			if _, err := m.readStageImage(context.Background(), "sing-box", "main"); err == nil {
				t.Fatal("unsafe draft read")
			}
			data, err := os.ReadFile(secret)
			if err != nil || string(data) != "preserve" {
				t.Fatal("outside file changed")
			}
		})
	}
}
