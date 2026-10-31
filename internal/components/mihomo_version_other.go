//go:build !linux

package components

import (
	"context"
	"github.com/ArtixSx/razvilka/internal/restorejournal"
)

func verifyMihomoArtifactRelease(context.Context, string, restorejournal.Image) error {
	return restorejournal.ErrUnavailable
}
