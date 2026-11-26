//go:build linux

package dataplane

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestMihomoLiveColdNewMarkersNeverReplaceConcurrentForeignName(t *testing.T) {
	for _, name := range []string{"retirement.json", "completed.json"} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			if e := os.Chmod(dir, 0700); e != nil {
				t.Fatal(e)
			}
			root, e := os.OpenRoot(dir)
			if e != nil {
				t.Fatal(e)
			}
			defer root.Close()
			var original os.FileInfo
			file, e := writeMihomoColdRetained(root, name, []byte("new documentary marker"), func() error {
				f, e := root.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
				if e != nil {
					return e
				}
				_, e = f.Write([]byte("foreign marker"))
				original, _ = f.Stat()
				return errors.Join(e, f.Close())
			})
			if file != nil {
				file.Close()
				t.Fatal("foreign name replaced")
			}
			if e == nil {
				t.Fatal("missing refusal")
			}
			after, e := os.Lstat(filepath.Join(dir, name))
			data, re := os.ReadFile(filepath.Join(dir, name))
			if e != nil || re != nil || !os.SameFile(original, after) || !bytes.Equal(data, []byte("foreign marker")) {
				t.Fatal("foreign marker changed", e, re)
			}
			entries, e := root.Open(".")
			if e != nil {
				t.Fatal(e)
			}
			names, e := entries.Readdirnames(-1)
			ce := entries.Close()
			if e != nil || ce != nil || len(names) != 1 || names[0] != name {
				t.Fatal("owned temporary not cleaned", names, e, ce)
			}
		})
	}
}
