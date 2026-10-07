package dataplane

import (
	"context"
	"path/filepath"

	"github.com/ArtixSx/razvilka/internal/netidentity"
)

// These detached observations are not receipts, ownership or effect authority.
type BackendInventorySnapshot = backendInventorySnapshot
type BackendInventoryCoverage = backendInventoryCoverage
type BackendInventoryRow = backendInventoryRow
type BackendNFTTable = backendNFTTable
type BackendNFTState = backendNFTState

const (
	BackendNFTUnknown                        = backendNFTUnknown
	BackendNFTEmpty                          = backendNFTEmpty
	BackendNFTPresent                        = backendNFTPresent
	BackendNFTNoRegisteredSubsystemAtCapture = backendNFTNoRegisteredSubsystemAtCapture
)

var ErrBackendInventoryUnknown = errBackendInventory

// RequireComplete is a coverage/absence predicate only. Consumers must still
// inspect all rows and enforce their held writer, ownership and effect guards.
func (s backendInventorySnapshot) RequireComplete() error { return s.requireLANBackendCoverage() }

// The caller retains its admitted tool descriptor throughout every Read.
// This constructor freezes its paths/hash/callback; it does not acquire a lease.
// Check must freshly verify the held protected review for both legacy aliases:
// exact paths, loader/extensions/environment and backend identity. A supplied
// review hash alone is not proof. Runner must implement the bounded read seam.
type BackendInventoryTools struct {
	Runner                            NFQWS2Runner
	IPTables, IP6Tables, ReviewSHA256 string
	Check                             func(context.Context, netidentity.Identity) error
}
type BackendInventory struct {
	reader backendInventoryReader
	review string
}

func NewBackendInventory(provider *netidentity.Provider, tools BackendInventoryTools) (*BackendInventory, error) {
	return newBackendInventory(provider, tools, backendNFTABILinux70)
}

// Explicit trusted startup selection of the separately reviewed stock NF ABI.
// Construction is not platform verification: every Read requires fresh stock
// Provider.WithCurrent identity and the compiled exact f77d10... review hash.
// No environment, persisted descriptor, uname-only or ENOENT fallback exists.
func NewReviewedStockNC1812BackendInventory(provider *netidentity.Provider, tools BackendInventoryTools) (*BackendInventory, error) {
	return newBackendInventory(provider, tools, backendNFTABIStockNC1812)
}
func newBackendInventory(provider *netidentity.Provider, tools BackendInventoryTools, abi backendNFTABI) (*BackendInventory, error) {
	if provider == nil || tools.Runner == nil || tools.Check == nil || !filepath.IsAbs(tools.IPTables) || !filepath.IsAbs(tools.IP6Tables) || tools.IPTables == tools.IP6Tables || !lanPolicyHash(tools.ReviewSHA256) {
		return nil, errBackendInventory
	}
	if _, ok := tools.Runner.(backendInventoryBoundedRunner); !ok {
		return nil, errBackendInventory
	}
	return &BackendInventory{review: tools.ReviewSHA256, reader: backendInventoryReader{Provider: provider, NFTABI: abi, Runner: tools.Runner, IPTables: tools.IPTables, IP6Tables: tools.IP6Tables, CheckTools: func(ctx context.Context, s backendInventoryScope) error { return tools.Check(ctx, s.Network) }}}, nil
}
func (r *BackendInventory) Read(ctx context.Context, expected netidentity.Identity) (BackendInventorySnapshot, error) {
	if r == nil {
		return BackendInventorySnapshot{}, errBackendInventory
	}
	return r.reader.Read(ctx, backendInventoryScope{Network: expected, ToolReviewID: r.review})
}
