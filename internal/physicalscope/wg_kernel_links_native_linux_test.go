//go:build linux

package physicalscope

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/netidentity"
)

// Coordinator-owned read-only native gate. No interface or kernel state is
// created/deleted; no WG private/public keys, MACs or real names are logged.
func TestNativeWGKernelLinkInventory(t *testing.T) {
	if os.Getenv("RAZVILKA_WG_KERNEL_LINK_READ") != "1" {
		t.Skip("coordinator-owned read-only kernel link gate")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	provider := netidentity.NewProcProvider()
	if os.Getenv("RAZVILKA_WG_KERNEL_LINK_STOCK") == "1" {
		var err error
		provider, err = netidentity.NewReviewedStockNC1812Provider(ctx)
		if err != nil {
			t.Fatal("actual reviewed stock provider unavailable")
		}
	}
	id, err := provider.Observe(ctx)
	if err != nil {
		t.Fatal("actual original namespace unavailable")
	}
	links, err := ReadWGKernelLinks(ctx, provider, id)
	if err != nil || len(links) == 0 {
		t.Fatal("actual complete kernel link inventory unavailable", err)
	}
	loopback := false
	for _, link := range links {
		loopback = loopback || link.Name == "lo"
	}
	if !loopback {
		t.Fatal("complete actual kernel inventory omitted loopback")
	}
	foreign := id
	foreign.BootID = "12345678-1234-1234-1234-123456789abc"
	if foreign.BootID == id.BootID {
		foreign.BootID = "23456789-1234-1234-1234-123456789abc"
	}
	if rows, err := ReadWGKernelLinks(ctx, provider, foreign); err == nil || len(rows) != 0 {
		t.Fatal("foreign namespace binding accepted")
	}
	cancel()
	if rows, err := ReadWGKernelLinks(ctx, provider, id); err == nil || len(rows) != 0 {
		t.Fatal("cancelled capture supplied facts")
	}
	t.Logf("actual readonly namespace-bound kernel inventory: links=%d; WG peer/service/mutation proof=false", len(links))
}
