//go:build linux && razvilka_native_fixture

package startuptools

import (
	"context"
	"os"

	"github.com/ArtixSx/razvilka/internal/netidentity"
)

// AcquireNativeFixtureManagedListPolicy uses the same fixed Ubuntu tool
// profile and actual protected producer as AcquireNativeFixturePolicy, with
// BOTH original managed-list WG aliases captured by acquireWG. Missing CLI
// entries are retained absence, not an inactivity conclusion; present CLI
// entries require actual ELF closure, held-fd --version and joined Wait.
// Only platform classification is modeled. No caller supplies WG images,
// arguments, availability, facts, runners or permission callbacks.
func AcquireNativeFixtureManagedListPolicy(ctx context.Context, provider *netidentity.Provider, reviewPath string) (*Lease, error) {
	ns, err := os.Readlink("/proc/self/ns/net")
	initial, otherErr := os.Readlink("/proc/1/ns/net")
	if os.Geteuid() != 0 || err != nil || otherErr != nil || ns == initial || provider == nil {
		return nil, ErrUnknown
	}
	p, err := nativeFixturePolicyProfile(reviewPath)
	if err != nil {
		return nil, err
	}
	p.id += "-managed-list"
	p.wgEngine = managedListWGProfile
	p.wgAliases = wgProfile(false, managedListWGProfile).wgAliases
	return acquireWG(ctx, provider, p)
}
