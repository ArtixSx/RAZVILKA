//go:build !linux

package dataplane

import (
	"context"
	"github.com/ArtixSx/razvilka/internal/operationgate"
)

func newMihomoLiveSidecar(context.Context, *mihomoLiveResource, ProcessSpec) (*mihomoLiveSidecar, error) {
	return nil, errMihomoLiveMaterial
}
func (*mihomoLiveSidecar) start(context.Context) error   { return errMihomoLiveMaterial }
func (*mihomoLiveSidecar) current(context.Context) error { return errMihomoLiveMaterial }
func (*mihomoLiveSidecar) observation(context.Context) (MihomoLiveRuntimeObservation, error) {
	return MihomoLiveRuntimeObservation{}, errMihomoLiveMaterial
}
func (*mihomoLiveSidecar) closeUnused() error { return errMihomoLiveMaterial }
func (*mihomoLiveSidecar) closeJoined() error { return errMihomoLiveMaterial }
func (*mihomoLiveSidecar) cleanup(context.Context, *operationgate.ExclusiveCleanupReview) error {
	return errMihomoLiveMaterial
}
