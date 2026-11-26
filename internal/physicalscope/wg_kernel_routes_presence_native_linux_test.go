//go:build linux

package physicalscope

import (
	"context"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/netidentity"
)

// Root supplies an independently owned disposable WG default table, or asks
// only for absence on stock firmware. This test never creates a route/link,
// loads a module or turns the detached count into WG/service/owner authority.
func TestNativeWGKernelServiceTablePresence(t *testing.T) {
	if os.Getenv("RAZVILKA_WG_KERNEL_SERVICE_READ") != "1" {
		t.Skip("coordinator-owned read-only numeric service-table observation")
	}
	table, err := strconv.Atoi(os.Getenv("RAZVILKA_WG_KERNEL_SERVICE_TABLE"))
	want, wantErr := strconv.Atoi(os.Getenv("RAZVILKA_WG_KERNEL_SERVICE_WANT"))
	iface := os.Getenv("RAZVILKA_WG_KERNEL_SERVICE_IFACE")
	if err != nil || wantErr != nil || table < 1 || uint64(table) > 0xffffffff || want != 0 && want != 1 || !interfaceName.MatchString(iface) {
		t.Fatal("explicit bounded query and expected count required")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 18*time.Second)
	defer cancel()
	provider := netidentity.NewProcProvider()
	if os.Getenv("RAZVILKA_WG_KERNEL_ROUTE_STOCK") == "1" {
		provider, err = netidentity.NewReviewedStockNC1812Provider(ctx)
		if err != nil {
			t.Fatal("actual reviewed stock provider unavailable")
		}
	}
	id, err := provider.Observe(ctx)
	if err != nil {
		t.Fatal("actual original namespace unavailable")
	}
	for _, family := range []int{4, 6} {
		count, err := ReadWGKernelServiceTable(ctx, provider, id, table, family, iface)
		if err != nil || count != want {
			t.Fatal("original complete numeric service-table observation refused; no ownership proof issued")
		}
	}
	t.Logf("actual_read_only_numeric_service_tables=true families=2 exact_count=%d kernel_reader=true CLI_JSON=false service_peer_owner_mutation_proof=false", want)
}
