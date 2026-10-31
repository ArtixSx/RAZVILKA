//go:build !linux

package components

import (
	"context"
	"github.com/ArtixSx/razvilka/internal/restorejournal"
)

func verifyMihomoArtifactRelease(context.Context, string, restorejournal.Image, func(context.Context, func() error) error) error {
	return restorejournal.ErrUnavailable
}
