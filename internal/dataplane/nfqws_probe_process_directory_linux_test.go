//go:build linux

package dataplane

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/ArtixSx/razvilka/internal/ownedfs"
)

func TestNFQWSProbePrivateDirectoryPreparation(t *testing.T) {
	for _, mode := range []string{"fresh", "public-parent", "symlink-leaf", "existing-receipt"} {
		t.Run(mode, func(t *testing.T) {
			base := t.TempDir()
			runtime := filepath.Join(base, "runtime")
			leaf := filepath.Join(runtime, "nfqws2")
			switch mode {
			case "public-parent":
				if err := os.Mkdir(runtime, 0755); err != nil {
					t.Fatal(err)
				}
			case "symlink-leaf":
				if err := os.Mkdir(runtime, 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(t.TempDir(), leaf); err != nil {
					t.Fatal(err)
				}
			case "existing-receipt":
				if err := os.MkdirAll(leaf, 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(leaf, "ownership.json"), []byte("foreign-unknown-state"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			root, err := ownedfs.Open(base)
			if err != nil {
				t.Fatal(err)
			}
			defer root.Close()
			err = prepareNFQWSProbePrivateDirectories(root)
			if mode == "public-parent" || mode == "symlink-leaf" {
				if err == nil {
					t.Fatal("foreign directory accepted")
				}
				if mode == "public-parent" {
					info, _ := os.Stat(runtime)
					if info.Mode().Perm() != 0755 {
						t.Fatal("foreign mode changed")
					}
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			info, err := os.Stat(leaf)
			if err != nil || info.Mode().Perm() != 0700 {
				t.Fatal(info, err)
			}
			if mode == "existing-receipt" {
				data, err := os.ReadFile(filepath.Join(leaf, "ownership.json"))
				if err != nil || string(data) != "foreign-unknown-state" {
					t.Fatal("inert directory preparation changed process receipt", err)
				}
			}
		})
	}
}
