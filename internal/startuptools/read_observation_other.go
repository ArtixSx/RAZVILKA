//go:build !linux || (!amd64 && !arm64)

package startuptools

import (
	"context"
	"github.com/ArtixSx/razvilka/internal/netidentity"
)

func (*Lease) WithReadOnlyToolObservation(context.Context, netidentity.Identity, string, func(context.Context) error) error {
	return at("READ_OBSERVATION_PLATFORM", nil)
}
