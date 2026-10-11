//go:build !linux || (!amd64 && !arm64)

package main

import (
	"context"

	"github.com/ArtixSx/razvilka/internal/dataplane"
)

func observeSelfUpdateRuntimePlatform(context.Context) (selfUpdateRuntimePlatformFacts, error) {
	return selfUpdateRuntimePlatformFacts{}, dataplane.ErrRuntimeInactivity
}
