//go:build linux && (amd64 || arm64)

package startuptools

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Actual retained local image/proc namespace + real kernel dump. The fixture
// carries a data-only source model, not a factory acceptance or WG peer proof.
func TestNativeWGKernelLinkOriginalHeldSource(t *testing.T) {
	if os.Getenv("RAZVILKA_WG_INACTIVITY_READ_CHILD") != "1" {
		t.Skip("coordinator-owned original retained source gate")
	}
	l, root := wgInactivityHeldChildFixture(t)
	r := &wgInactivityRunner{lease: l, engine: "wireguard"}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	links, err := r.ReadWGKernelLinks(ctx, l.identity)
	if err != nil || len(links) == 0 {
		t.Fatal("original retained source refused actual kernel dump", err)
	}
	if _, err := os.Lstat(filepath.Join(root, "started")); !os.IsNotExist(err) {
		t.Fatal("kernel observer executed the modeled CLI")
	}
	if err := os.WriteFile(l.profile.ipAlias, []byte("changed held source bytes"), 0700); err != nil {
		t.Fatal(err)
	}
	if rows, err := r.ReadWGKernelLinks(ctx, l.identity); err == nil || len(rows) != 0 {
		t.Fatal("changed held source retained observation authority")
	}
}
