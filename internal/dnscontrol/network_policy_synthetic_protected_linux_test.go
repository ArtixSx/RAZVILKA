//go:build linux

package dnscontrol

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Filesystem-only tests, no sockets or native effects. NET cross-compiles;
// Linux execution belongs to Root.
func TestSyntheticDNSProtectedRootRefusesWritableParentOrLeaf(t *testing.T) {
	for _, kind := range []string{"root", "parent"} {
		t.Run(kind, func(t *testing.T) {
			f := syntheticDNSModelFixture(t, nil)
			parent := t.TempDir()
			root := filepath.Join(parent, "dns-scoped")
			if err := os.Mkdir(root, 0700); err != nil {
				t.Fatal(err)
			}
			changed := root
			if kind == "parent" {
				changed = parent
			}
			if err := os.Chmod(changed, 0777); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.Chmod(changed, 0700) })
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if _, err := NewNetworkPolicyDNSSyntheticResolver(ctx, context.Background(), f.r, f.control, root, f.definition, nil); err == nil {
				t.Fatal("writable reservation path accepted")
			}
		})
	}
}

func TestSyntheticDNSProtectedModeRestorationCannotReviveSource(t *testing.T) {
	f := syntheticDNSModelFixture(t, nil)
	s := f.source(t, nil)
	if err := os.Chmod(f.root, 0777); err != nil {
		t.Fatal(err)
	}
	if err := s.current(context.Background()); err == nil {
		t.Fatal("writable root remained current")
	}
	if err := os.Chmod(f.root, 0700); err != nil {
		t.Fatal(err)
	}
	if err := s.current(context.Background()); err == nil {
		t.Fatal("mode restoration revived original")
	}
}
