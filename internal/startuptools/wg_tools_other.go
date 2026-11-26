//go:build !linux || (!amd64 && !arm64)

package startuptools

import (
	"context"
	"github.com/ArtixSx/razvilka/internal/netidentity"
)

func acquireWG(context.Context, *netidentity.Provider, profile) (*Lease, error) {
	return nil, at("WG_PLATFORM", nil)
}
func (*Lease) runWG(context.Context, string, string, ...string) ([]byte, error) {
	return nil, at("WG_PLATFORM", nil)
}
