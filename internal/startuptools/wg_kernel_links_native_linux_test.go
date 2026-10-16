//go:build linux && (amd64 || arm64)

package startuptools

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

const wgKernelLinkMetadataAlias = "wg-kernel-link-metadata-"

// Only private held test-binary aliases answer these exact metadata commands.
// These bytes model the profile's version checks, not installed host tools.
func init() {
	alias := filepath.Base(os.Args[0])
	switch alias {
	case wgKernelLinkMetadataAlias + "ip":
		if len(os.Args) != 2 || os.Args[1] != "-Version" {
			os.Exit(99)
		}
		fmt.Fprint(os.Stdout, ubuntuPolicyProfile().ipVersion)
		os.Exit(0)
	case wgKernelLinkMetadataAlias + "iptables", wgKernelLinkMetadataAlias + "ip6tables":
		if len(os.Args) != 2 || os.Args[1] != "--version" {
			os.Exit(99)
		}
		name := "iptables"
		if alias == wgKernelLinkMetadataAlias+"ip6tables" {
			name = "ip6tables"
		}
		fmt.Fprintf(os.Stdout, "%s v%s\n", name, ubuntuProfile().version)
		os.Exit(0)
	}
}

// The older diagnostic-only fixture intentionally has no xtables entries and
// cannot pass full Lease.Check. This separate fixture pins all three private
// metadata helpers so the production opening/closing checks run unchanged.
func wgKernelLinkHeldSourceFixture(t *testing.T) (*Lease, string) {
	t.Helper()
	l, root := wgInactivityHeldChildFixture(t)
	data, err := os.ReadFile(l.profile.ipAlias)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(data)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	for i, name := range []string{"iptables", "ip6tables", "ip"} {
		path := filepath.Join(root, wgKernelLinkMetadataAlias+name)
		if err := os.WriteFile(path, data, 0700); err != nil {
			t.Fatal(err)
		}
		file, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		info, err := file.Stat()
		if err != nil {
			file.Close()
			t.Fatal(err)
		}
		hash, err := hashImage(ctx, file, info.Size())
		if err != nil {
			file.Close()
			t.Fatal(err)
		}
		image := &heldImage{path: path, file: file, info: info, hash: hash}
		l.review.images[path] = image
		if i < 2 {
			l.profile.aliases[i], l.review.entry[i] = path, image
		} else {
			l.profile.ipAlias, l.review.ipEntry = path, image
		}
	}
	l.profile.ipVersion = ubuntuPolicyProfile().ipVersion
	l.review.profile = l.profile
	return l, root
}

// Actual retained local image/proc namespace + real kernel dump. The fixture
// carries a data-only source/version model, not factory or WG peer acceptance.
func TestNativeWGKernelLinkOriginalHeldSource(t *testing.T) {
	if os.Getenv("RAZVILKA_WG_INACTIVITY_READ_CHILD") != "1" {
		t.Skip("coordinator-owned original retained source gate")
	}
	l, root := wgKernelLinkHeldSourceFixture(t)
	r := &wgInactivityRunner{lease: l, engine: "wireguard"}
	// Two independently bounded observations exercise both original wrappers.
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := l.Check(ctx, l.identity); err != nil {
		t.Fatal("private held metadata fixture incomplete", err)
	}
	links, err := r.ReadWGKernelLinks(ctx, l.identity)
	if err != nil || len(links) == 0 {
		t.Fatal("original retained source refused actual kernel dump", err)
	}
	forward := &wgRunner{lease: l, engine: "wireguard"}
	if rows, err := forward.ReadWGKernelLinks(ctx, l.identity); err != nil || len(rows) == 0 {
		t.Fatal("original forward source refused actual kernel dump", err)
	}
	if _, err := os.Lstat(filepath.Join(root, "started")); !os.IsNotExist(err) {
		t.Fatal("kernel observer executed the modeled route/effect CLI")
	}
	if err := os.WriteFile(l.profile.ipAlias, []byte("changed held source bytes"), 0700); err != nil {
		t.Fatal(err)
	}
	if rows, err := r.ReadWGKernelLinks(ctx, l.identity); err == nil || len(rows) != 0 {
		t.Fatal("changed held source retained observation authority")
	}
	if rows, err := forward.ReadWGKernelLinks(ctx, l.identity); err == nil || len(rows) != 0 {
		t.Fatal("changed held forward source retained observation authority")
	}
}
