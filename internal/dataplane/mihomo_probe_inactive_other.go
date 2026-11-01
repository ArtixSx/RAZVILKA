//go:build !linux

package dataplane

import (
	"context"

	"github.com/ArtixSx/razvilka/internal/netidentity"
)

func observeMihomoProbeInactive(context.Context, *netidentity.Provider) error {
	return ErrRuntimeInactivity
}
