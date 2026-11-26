package startuptools

import (
	"context"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/netidentity"
)

func TestWGKernelServiceTableSourcesRequireOriginalLeaseScopeAndLifetime(t *testing.T) {
	id := netidentity.Identity{Version: 1, Kind: netidentity.ProcNetInode, BootID: "12345678-1234-1234-1234-123456789abc", Inode: 7}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	for _, r := range []*wgRunner{nil, {}, {lease: unitLease(t), engine: "foreign"}, {lease: unitLease(t), engine: "wireguard"}} {
		if n, err := r.ReadWGKernelServiceTable(ctx, id, 206, 4, "rz-wg"); n != 0 || err == nil {
			t.Fatal("unissued forward source produced presence")
		}
	}
	for _, r := range []*wgInactivityRunner{nil, {}, {lease: unitLease(t), engine: "foreign"}, {lease: unitLease(t), engine: "wireguard"}} {
		if n, err := r.ReadWGKernelServiceTable(ctx, id, 206, 4, "rz-wg"); n != 0 || err == nil {
			t.Fatal("unissued inactivity source produced presence")
		}
	}
	r := &wgRunner{lease: unitLease(t), engine: "wireguard"}
	if err := r.lease.Close(); err != nil {
		t.Fatal(err)
	}
	if n, err := r.ReadWGKernelServiceTable(ctx, id, 206, 4, "rz-wg"); n != 0 || err == nil {
		t.Fatal("closed source revived presence")
	}
}
