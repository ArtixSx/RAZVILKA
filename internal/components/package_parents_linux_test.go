//go:build linux

package components

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestPackageParentRestoresOnlyHeldOwnership(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires real root chown")
	}
	base := t.TempDir()
	etc := filepath.Join(base, "etc")
	if err := os.Mkdir(etc, 0755); err != nil {
		t.Fatal(err)
	}
	held, err := protectPackageParents([]string{base, etc})
	if err != nil {
		t.Fatal(err)
	}
	child := filepath.Join(etc, "package-file")
	if err := os.WriteFile(child, []byte("package"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{base, etc, child} {
		if err := os.Chown(path, 1001, 1001); err != nil {
			t.Fatal(err)
		}
	}
	if err := finishPackageParents(held); err != nil {
		t.Fatal(err)
	}
	for _, p := range held {
		info, _ := os.Stat(p.path)
		stat := info.Sys().(*syscall.Stat_t)
		if stat.Uid != uint32(p.uid) || stat.Gid != uint32(p.gid) || info.Mode() != p.info.Mode() || !os.SameFile(p.info, info) {
			t.Fatal("parent metadata not restored")
		}
	}
	info, _ := os.Stat(child)
	if info.Sys().(*syscall.Stat_t).Uid != 1001 {
		t.Fatal("recursive ownership repair touched package content")
	}
}

func TestPackageParentRejectsUnsafeBaselineAndReplacement(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires real root chown")
	}
	for _, kind := range []string{"foreign-baseline", "writable-baseline", "replacement", "symlink", "changed-mode"} {
		t.Run(kind, func(t *testing.T) {
			base := t.TempDir()
			path := filepath.Join(base, "etc")
			if err := os.Mkdir(path, 0755); err != nil {
				t.Fatal(err)
			}
			if kind == "foreign-baseline" {
				if err := os.Chown(path, 1001, 1001); err != nil {
					t.Fatal(err)
				}
			}
			if kind == "writable-baseline" {
				if err := os.Chmod(path, 0777); err != nil {
					t.Fatal(err)
				}
			}
			held, err := protectPackageParents([]string{path})
			if kind == "foreign-baseline" || kind == "writable-baseline" {
				if err == nil {
					_ = finishPackageParents(held)
					t.Fatal("unsafe baseline adopted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if kind == "changed-mode" {
				if err := os.Chmod(path, 0777); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := os.Rename(path, path+"-old"); err != nil {
					t.Fatal(err)
				}
				if kind == "symlink" {
					err = os.Symlink(path+"-old", path)
				} else {
					err = os.Mkdir(path, 0755)
				}
				if err != nil {
					t.Fatal(err)
				}
			}
			before, err := os.Lstat(path)
			if err != nil {
				t.Fatal(err)
			}
			if err := finishPackageParents(held); err == nil {
				t.Fatal("changed parent accepted")
			}
			after, err := os.Lstat(path)
			if err != nil || !os.SameFile(before, after) || before.Mode() != after.Mode() ||
				before.Sys().(*syscall.Stat_t).Uid != after.Sys().(*syscall.Stat_t).Uid ||
				before.Sys().(*syscall.Stat_t).Gid != after.Sys().(*syscall.Stat_t).Gid {
				t.Fatal("refusal changed replacement metadata", err)
			}
		})
	}
}
