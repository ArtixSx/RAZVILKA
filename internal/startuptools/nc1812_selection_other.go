//go:build !linux || (!amd64 && !arm64)

package startuptools

import (
	"context"

	"github.com/ArtixSx/razvilka/internal/netidentity"
)

func acquireNC1812Selected(context.Context, *netidentity.Provider, nc1812ToolSet) (*Lease, error) {
	return nil, at("ACQUIRE_PLATFORM", nil)
}
