package components

import (
	"context"

	"github.com/ArtixSx/razvilka/internal/operationgate"
	"github.com/ArtixSx/razvilka/internal/restorejournal"
)

// This hashes the complete controller, managed binary and pool artifact as
// before. Only a second hash of the SAME physical pool inode is replaced by
// the actual hash-reader's bounded comparison. It never changes Current or
// any Start/cleanup effect path and carries no proof outside this call.
func (p *MihomoLiveProcess) currentNativeReadComparison(ctx context.Context, cleanup *operationgate.ExclusiveCleanupReview) error {
	if p == nil || p.self != p {
		return ErrMihomoLiveOwner
	}
	if err := mihomoLiveFinite(ctx); err != nil {
		return err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || p.closeErr != nil || p.native == nil || p.source == nil {
		return ErrMihomoLiveOwner
	}
	if cleanup != nil {
		if err := p.control.CurrentForCleanupOperation(ctx, cleanup); err != nil {
			return err
		}
	}
	p.source.mu.Lock()
	defer p.source.mu.Unlock()
	return p.source.currentComparedLocked(ctx, func(held context.Context, proof *restorejournal.ArtifactSourceComparison) error {
		return p.native.currentCompared(held, cleanup, proof)
	})
}
