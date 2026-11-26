//go:build linux

package dataplane

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestMihomoLiveColdMoveRetainsActualInodesAcrossLostACK(t *testing.T) {
	for _, cut := range []string{"runtime-renamed", "runtime-directory-ack"} {
		t.Run(cut, func(t *testing.T) {
			base := filepath.Join(t.TempDir(), "state")
			if err := os.Mkdir(base, 0700); err != nil {
				t.Fatal(err)
			}
			a := &ProxyTunnelAdapter{EngineID: "mihomo", StateRoot: filepath.Join(base, "mihomo"), SidecarKind: "hev"}
			if err := os.MkdirAll(a.runtimeRoot(), 0700); err != nil {
				t.Fatal(err)
			}
			data := []byte("archived private runtime bytes")
			if err := os.WriteFile(a.engineConfigPath(), data, 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(filepath.Join(base, "archive"), 0700); err != nil {
				t.Fatal(err)
			}
			root, err := os.OpenRoot(base)
			if err != nil {
				t.Fatal(err)
			}
			defer root.Close()
			archive, err := root.OpenRoot("archive")
			if err != nil {
				t.Fatal(err)
			}
			defer archive.Close()
			before, err := readMihomoColdRuntime(root, "mihomo", a)
			if err != nil {
				t.Fatal(err)
			}
			guardCalls := 0
			guard := func() error { guardCalls++; return checkRetirementChild(root, "archive", archive) }
			lost := errors.New("lost actual durability ACK")
			err = moveMihomoColdRuntime(root, archive, a, before, guard, func(stage string) error {
				if stage == cut {
					return lost
				}
				return nil
			})
			if !errors.Is(err, lost) {
				t.Fatal("fault absent", err)
			}
			if _, err := root.Lstat("mihomo"); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("source not moved", err)
			}
			if err := moveMihomoColdRuntime(root, archive, a, before, guard, nil); err != nil {
				t.Fatal("fresh original retry", err)
			}
			after, err := readMihomoColdRuntime(archive, "runtime", a)
			name := mihomoColdRelative(a, a.engineConfigPath())
			if err != nil || before.Identity != after.Identity || before.FileIdentities[name] != after.FileIdentities[name] || !bytes.Equal(after.Files[name], data) || guardCalls < 4 {
				t.Fatal("original history lost", err)
			}
			path := filepath.Join("runtime", name)
			f, err := archive.OpenFile(path+".replacement", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := f.Write(data); err != nil {
				t.Fatal(err)
			}
			if err := f.Close(); err != nil {
				t.Fatal(err)
			}
			if err := archive.Rename(path+".replacement", path); err != nil {
				t.Fatal(err)
			}
			if moveMihomoColdRuntime(root, archive, a, before, guard, nil) == nil {
				t.Fatal("same bytes foreign inode adopted")
			}
		})
	}
}

func TestMihomoLiveColdMoveCannotReplaceExistingArchive(t *testing.T) {
	base := filepath.Join(t.TempDir(), "state")
	if err := os.Mkdir(base, 0700); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"mihomo", "archive", "archive/runtime"} {
		if err := os.Mkdir(filepath.Join(base, p), 0700); err != nil {
			t.Fatal(err)
		}
	}
	root, err := os.OpenRoot(base)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	archive, err := root.OpenRoot("archive")
	if err != nil {
		t.Fatal(err)
	}
	defer archive.Close()
	a := &ProxyTunnelAdapter{EngineID: "mihomo", StateRoot: filepath.Join(base, "mihomo")}
	before, err := readMihomoColdRuntime(root, "mihomo", a)
	if err != nil {
		t.Fatal(err)
	}
	original, err := archive.Stat("runtime")
	if err != nil {
		t.Fatal(err)
	}
	if moveMihomoColdRuntime(root, archive, a, before, func() error { return nil }, nil) == nil {
		t.Fatal("existing destination accepted")
	}
	after, err := archive.Stat("runtime")
	if err != nil || !os.SameFile(original, after) {
		t.Fatal("foreign archive replaced", err)
	}
	from, err := root.Open(".")
	if err != nil {
		t.Fatal(err)
	}
	defer from.Close()
	to, err := archive.Open(".")
	if err != nil {
		t.Fatal(err)
	}
	defer to.Close()
	if err := mihomoColdRenameNoReplace(from, to); !errors.Is(err, os.ErrExist) {
		t.Fatal("native no-replace not enforced", err)
	}
}
