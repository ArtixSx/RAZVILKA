//go:build !linux

package dataplane

import (
	"context"

	"github.com/ArtixSx/razvilka/internal/netidentity"
)

func readSyntheticConntrack(context.Context, netidentity.Identity) (syntheticCTImage, error) {
	return syntheticCTImage{}, errSyntheticConntrack
}
