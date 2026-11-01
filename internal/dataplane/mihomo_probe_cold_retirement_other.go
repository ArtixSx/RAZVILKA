//go:build !linux

package dataplane

import (
	"context"
	"github.com/ArtixSx/razvilka/internal/netidentity"
)

func observeMihomoColdAbsence(context.Context, *netidentity.Provider, ExecutionMihomoProbeDefinition, string) (netidentity.Identity, error) {
	return netidentity.Identity{}, ErrMihomoProbeRetirement
}
