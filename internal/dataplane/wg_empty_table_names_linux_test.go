//go:build linux

package dataplane

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestWGEmptyTableStock44NameSourcesRefuseSymlinks(t *testing.T) {
	previous := rtTablesSources
	defer func() { rtTablesSources = previous }()
	for _, where := range []string{"root", "table-file", "directory", "nested-file"} {
		t.Run(where, func(t *testing.T) {
			root, foreign := t.TempDir(), t.TempDir()
			path, target := filepath.Join(root, "rt_tables"), filepath.Join(foreign, "table")
			if err := os.WriteFile(target, []byte("255 local\n"), 0600); err != nil {
				t.Fatal(err)
			}
			switch where {
			case "root":
				path, target = filepath.Join(root, "alias"), foreign
				root = path
			case "directory":
				path, target = filepath.Join(root, "rt_tables.d"), foreign
			case "nested-file":
				directory := filepath.Join(root, "rt_tables.d")
				if err := os.Mkdir(directory, 0700); err != nil {
					t.Fatal(err)
				}
				path = filepath.Join(directory, "alias.conf")
			}
			if err := os.Symlink(target, path); err != nil {
				t.Fatal(err)
			}
			rtTablesSources = []string{root}
			if _, err := wgEmptyTableNames(context.Background(), 206); err == nil {
				t.Fatal("symlink name source passed query selection guard", where)
			}
		})
	}
}
