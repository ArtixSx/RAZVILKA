//go:build !linux || (!amd64 && !arm64)

package startuptools

import (
	"context"

	"github.com/ArtixSx/razvilka/internal/netidentity"
)

func acquire(context.Context, *netidentity.Provider, profile) (*Lease, error) {
	return nil, at("ACQUIRE_PLATFORM", nil)
}
func (*Lease) current(context.Context, netidentity.Identity, bool) error {
	return at("CHECK_PLATFORM", nil)
}
func (*Lease) RunBounded(context.Context, string, int, ...string) ([]byte, error) {
	return nil, at("READ_PLATFORM", nil)
}
