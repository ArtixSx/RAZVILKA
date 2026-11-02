package components

import (
	"context"
	"github.com/ArtixSx/razvilka/internal/operationgate"
)

// ProfileReferenceForCleanup exposes only this retained child's original
// profile comparison, under an actual cleanup borrower. It grants no Start,
// forward Current, service evidence or reconstructed process owner.
func (p *MihomoLiveProcess) ProfileReferenceForCleanup(ctx context.Context, cleanup *operationgate.ExclusiveCleanupReview) (MihomoLiveProfileReference, error) {
	if err := p.CurrentForCleanup(ctx, cleanup); err != nil {
		return MihomoLiveProfileReference{}, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || p.closeErr != nil || p.source == nil || p.profile == nil {
		return MihomoLiveProfileReference{}, ErrMihomoLiveOwner
	}
	return p.source.ReviewProfileReference(ctx, p.profile)
}
