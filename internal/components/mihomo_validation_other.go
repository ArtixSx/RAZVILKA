//go:build !linux

package components

import (
	"context"
	"github.com/ArtixSx/razvilka/internal/restorejournal"
)

func nativeValidateMihomoProfile(context.Context, string, restorejournal.Image, []byte, func(context.Context, func() error) error) error {
	return restorejournal.ErrUnavailable
}
