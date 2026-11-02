//go:build !linux

package dataplane

import (
	"context"
	"github.com/ArtixSx/razvilka/internal/netidentity"
)

func observeMihomoColdHome(context.Context, ExecutionMihomoLiveDefinition, func(context.Context) (netidentity.Identity, error)) (mihomoColdHomeArchive, error) {
	return mihomoColdHomeArchive{}, ErrMihomoLiveRetirement
}
