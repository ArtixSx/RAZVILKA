//go:build !linux

package dataplane

import (
	"context"
	"github.com/ArtixSx/razvilka/internal/netidentity"
)

func observeMihomoLiveColdProcesses(context.Context, *netidentity.Provider, ExecutionMihomoLiveDefinition, string) (netidentity.Identity, error) {
	return netidentity.Identity{}, ErrMihomoProbeRetirement
}
