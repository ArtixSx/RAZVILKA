//go:build linux

package dataplane

import (
	"os"
	"path/filepath"
	"testing"
)

// Actual original directory FDs and fresh membership observations only. This
// comparison fixture issues no native cleanup or opaque original CORE source.
func TestMihomoSameBootStaticFreshMembership(t *testing.T) {
	for _, kind := range []string{"growing-log", "new-generation", "new-file", "missing-file", "foreign-directory", "symlink", "copied", "closed"} {
		t.Run(kind, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "private")
			if err := os.Mkdir(path, 0700); err != nil {
				t.Fatal(err)
			}
			for _, name := range []string{"runtime", "policy-generations"} {
				if err := os.Mkdir(filepath.Join(path, name), 0700); err != nil {
					t.Fatal(err)
				}
			}
			log := filepath.Join(path, "runtime", "sidecar.log")
			if err := os.WriteFile(log, []byte("original"), 0600); err != nil {
				t.Fatal(err)
			}
			root, err := openBootRetirementRoot(path)
			if err != nil {
				t.Fatal(err)
			}
			c := &mihomoSameBootStatic{root: root, dirs: map[string]*os.Root{}, infos: map[string]os.FileInfo{}, members: map[string]map[string]bool{".": {"runtime": true, "policy-generations": true}, "runtime": {"sidecar.log": false}, "policy-generations": {}}}
			c.self = c
			defer c.close()
			for _, name := range []string{"runtime", "policy-generations"} {
				dir, err := openRetirementChild(root, name)
				if err != nil {
					t.Fatal(err)
				}
				c.dirs[name] = dir
				c.infos[name], err = dir.Stat(".")
				if err != nil {
					t.Fatal(err)
				}
			}
			if err := c.membersCurrent(); err != nil {
				t.Fatal("original member set refused", err)
			}
			switch kind {
			case "growing-log":
				if err := os.WriteFile(log, []byte("original log continues while genuine process exits"), 0600); err != nil {
					t.Fatal(err)
				}
			case "new-generation":
				if err := os.Mkdir(filepath.Join(path, "policy-generations", "11111111111111111111111111111111"), 0700); err != nil {
					t.Fatal(err)
				}
			case "new-file":
				if err := os.WriteFile(filepath.Join(path, "runtime", "foreign"), nil, 0600); err != nil {
					t.Fatal(err)
				}
			case "missing-file":
				if err := os.Remove(log); err != nil {
					t.Fatal(err)
				}
			case "foreign-directory":
				if err := os.Rename(filepath.Join(path, "runtime"), filepath.Join(filepath.Dir(path), "old-runtime")); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(filepath.Join(path, "runtime"), 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(log, []byte("original"), 0600); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				if err := os.Remove(log); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink("/dev/null", log); err != nil {
					t.Fatal(err)
				}
			case "copied":
				copy := *c // No lock-bearing fields; exact self pointer must refuse.
				if err := copy.membersCurrent(); err == nil {
					t.Fatal("copied observer accepted")
				}
				return
			case "closed":
				if err := c.close(); err != nil {
					t.Fatal(err)
				}
			}
			err = c.membersCurrent()
			if kind == "growing-log" {
				if err != nil {
					t.Fatal("log body growth changed membership", err)
				}
				return
			}
			if err == nil {
				t.Fatal("changed original member set accepted", kind)
			}
		})
	}
}
