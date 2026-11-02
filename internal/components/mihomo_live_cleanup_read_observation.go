package components

import (
	"context"
	"errors"
	"os"

	"github.com/ArtixSx/razvilka/internal/operationgate"
)

// MihomoLiveCleanupObservation is exclusively a read comparison under the
// same original child's fresh cleanup review. It cannot become a forward
// observation, expose the child or perform cleanup, Start or packet effects.
type MihomoLiveCleanupObservation struct {
	self    *MihomoLiveCleanupObservation
	inner   *MihomoLiveObservation
	cleanup *operationgate.ExclusiveCleanupReview
}

func (p *MihomoLiveProcess) WithCleanupReadObservation(ctx context.Context, cleanup *operationgate.ExclusiveCleanupReview, read func(context.Context, *MihomoLiveCleanupObservation) error) (result error) {
	if read == nil || cleanup == nil {
		return ErrMihomoLiveOwner
	}
	if err := p.CurrentForCleanup(ctx, cleanup); err != nil {
		return err
	}
	inner := &MihomoLiveObservation{child: p, source: p.source, open: true}
	inner.self = inner
	inner.ctx = context.WithValue(ctx, mihomoLiveObservationKey{}, inner)
	v := &MihomoLiveCleanupObservation{inner: inner, cleanup: cleanup}
	v.self = v
	defer func() {
		inner.mu.Lock()
		inner.open = false
		inner.mu.Unlock()
		result = errors.Join(result, p.CurrentForCleanup(ctx, cleanup))
	}()
	return read(inner.ctx, v)
}

func (v *MihomoLiveCleanupObservation) valid() bool {
	return v != nil && v.self == v && v.inner != nil && v.cleanup != nil
}
func (v *MihomoLiveCleanupObservation) Current(ctx context.Context) error {
	if !v.valid() {
		return ErrMihomoLiveOwner
	}
	return v.inner.current(ctx, v.cleanup)
}
func (v *MihomoLiveCleanupObservation) BoundTo(child *MihomoLiveProcess, source *MihomoLiveSource, cleanup *operationgate.ExclusiveCleanupReview) bool {
	return v.valid() && v.cleanup == cleanup && v.inner.BoundTo(child, source)
}
func (v *MihomoLiveCleanupObservation) ProfileReference(ctx context.Context) (MihomoLiveProfileReference, error) {
	if err := v.Current(ctx); err != nil {
		return MihomoLiveProfileReference{}, err
	}
	return v.inner.profileReferenceRead(ctx)
}
func (v *MihomoLiveCleanupObservation) PID() int {
	if !v.valid() {
		return 0
	}
	return v.inner.PID()
}
func (v *MihomoLiveCleanupObservation) MatchesFile(kind string, info os.FileInfo) bool {
	return v.valid() && v.inner.MatchesFile(kind, info)
}
