//go:build !linux

package dataplane

import (
	"context"
	"github.com/ArtixSx/razvilka/internal/operationgate"
)

func (*mihomoLiveResource) nativeCurrent(context.Context) error { return errMihomoLiveMaterial }
func (*mihomoLiveResource) nativeCleanupCurrent(context.Context, *operationgate.ExclusiveCleanupReview) error {
	return errMihomoLiveMaterial
}
