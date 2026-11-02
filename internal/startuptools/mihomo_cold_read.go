package startuptools

import (
	"context"
	"github.com/ArtixSx/razvilka/internal/dataplane"
)

// Comparison projection of the original held lease, never another acquisition.
// The only executor exposed for offline retirement is the closed read-only ABI.
func (l *Lease) MihomoColdReadTools() (any, dataplane.SyntheticDNSCommandTools, string, error) {
	d, err := l.SyntheticDNSCommandTools()
	if err != nil {
		return nil, dataplane.SyntheticDNSCommandTools{}, "", err
	}
	inventory, err := l.InventoryTools()
	if err != nil || inventory.ReviewSHA256 != d.ReviewSHA256 || inventory.IPTables != d.IPTables {
		return nil, dataplane.SyntheticDNSCommandTools{}, "", at("MIHOMO_COLD_SOURCE", err)
	}
	return l, d, inventory.IP6Tables, nil
}
func (l *Lease) RunMihomoColdRead(ctx context.Context, name string, args ...string) ([]byte, error) {
	return l.runMihomoLiveRead(ctx, name, args...)
}
