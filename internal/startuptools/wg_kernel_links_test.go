package startuptools

import (
	"context"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/netidentity"
)

func TestWGKernelLinkSourceRefusesUnissuedWrongEngineScopeAndLifetime(t *testing.T) {
	id := netidentity.Identity{Version: 1, Kind: netidentity.ProcNetInode, BootID: "12345678-1234-1234-1234-123456789abc", Inode: 7}
	c, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	for _, r := range []*wgInactivityRunner{nil, {}, {lease: unitLease(t), engine: "foreign"}, {lease: unitLease(t), engine: "wireguard"}} {
		links, err := r.ReadWGKernelLinks(c, id)
		if err == nil || len(links) != 0 {
			t.Fatal("unissued source produced kernel inventory")
		}
	}
	r := &wgInactivityRunner{lease: unitLease(t), engine: "wireguard"}
	if err := r.lease.Close(); err != nil {
		t.Fatal(err)
	}
	if links, err := r.ReadWGKernelLinks(c, id); err == nil || len(links) != 0 {
		t.Fatal("closed lease revived kernel observation")
	}
}
