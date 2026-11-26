//go:build linux

package components

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNFQWSInitialParentDirectoryOwnership(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("actual root/nonroot ownership adversaries require root")
	}
	for _, variant := range []string{"root-group1001-protected", "nonroot-owner", "group-writable", "symlink"} {
		t.Run(variant, func(t *testing.T) {
			prefix := filepath.Join(t.TempDir(), "opt")
			parent := filepath.Join(prefix, "etc", "init.d")
			if err := os.MkdirAll(parent, 0755); err != nil {
				t.Fatal(err)
			}
			if err := os.Chown(parent, 0, 1001); err != nil {
				t.Fatal(err)
			}
			switch variant {
			case "nonroot-owner":
				if err := os.Chown(parent, 1001, 1001); err != nil {
					t.Fatal(err)
				}
			case "group-writable":
				if err := os.Chmod(parent, 0775); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				other := filepath.Join(prefix, "etc", "other")
				if err := os.Rename(parent, other); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink("other", parent); err != nil {
					t.Fatal(err)
				}
			}
			m := &Manager{}
			root, err := m.openNFQWSInitialPrefix(prefix)
			if root != nil {
				_ = root.Close()
			}
			if (err == nil) != (variant == "root-group1001-protected") {
				t.Fatal("existing parent ownership boundary", variant, err)
			}
		})
	}
	// Directory admission does not relax the derivative's exact payload
	// ownership contract: the same root:1001 regular file remains unsupported.
	payload := filepath.Join(t.TempDir(), "payload")
	if err := os.WriteFile(payload, []byte("reviewed bytes"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(payload, 0, 1001); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(payload)
	if err != nil || nfqwsInitialMetadata(info, false) == nil {
		t.Fatal("existing parent exception leaked to payload readback", err)
	}
}
