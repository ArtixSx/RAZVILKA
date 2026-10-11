package app

import (
	"context"
	"reflect"

	"github.com/ArtixSx/razvilka/internal/config"
)

// These transitions consume only the actual SAME Store's single-service
// writer/undo receipt. They retain the original ScopeReview and physical
// Review, and supply no node proof, effect admission or cleanup permission.
func (b *ListScopeBinding) AcceptAutonomyCommitted(ctx context.Context, receipt *config.AutonomyRouteCommitReview) error {
	return b.acceptAutonomyTransition(ctx, receipt, false)
}

func (b *ListScopeBinding) AcceptAutonomyRestored(ctx context.Context, receipt *config.AutonomyRouteCommitReview) error {
	return b.acceptAutonomyTransition(ctx, receipt, true)
}

func (b *ListScopeBinding) acceptAutonomyTransition(ctx context.Context, receipt *config.AutonomyRouteCommitReview, restored bool) error {
	if b == nil || b.self != b || b.app == nil {
		return ErrListScopeChanged
	}
	c, cancel, err := listScopeContext(ctx)
	if cancel != nil {
		defer cancel()
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if err != nil {
		return b.changed(err)
	}
	err = b.app.Operations.WithExclusiveContext(c, func() error {
		if b.closed || b.invalid || b.scope == nil || b.app.Store != b.store || !receipt.MatchesStore(b.store) {
			return b.changed(nil)
		}
		read := receipt.CommittedImages
		accept := b.scope.AcceptAutonomyCommitted
		if restored {
			read, accept = receipt.RestoredImages, b.scope.AcceptAutonomyRestored
		}
		before, after, err := read(c)
		if err != nil || !reflect.DeepEqual(before, b.expected) || !reflect.DeepEqual(before.NetworkPolicy, after.NetworkPolicy) || !reflect.DeepEqual(before.DefaultRouteConsent, after.DefaultRouteConsent) {
			return b.changed(err)
		}
		// The original scope owner consumes the sealed Store transition first.
		// Its physical selection is unchanged; full verification below uses
		// the SAME Observer/Review instead of reopening after publication.
		if err := accept(c, receipt); err != nil {
			return b.changed(err)
		}
		closingBefore, closingAfter, err := read(c)
		if err != nil || !reflect.DeepEqual(before, closingBefore) || !reflect.DeepEqual(after, closingAfter) {
			return b.changed(err)
		}
		b.expected = closingAfter
		if err := b.currentLocked(c); err != nil {
			return err
		}
		// Physical/WAN callbacks have now joined. The actual receipt phase and
		// full Store image must still close this SAME publication or undo.
		finalBefore, finalAfter, err := read(c)
		if err != nil || !reflect.DeepEqual(before, finalBefore) || !reflect.DeepEqual(after, finalAfter) {
			return b.changed(err)
		}
		return nil
	})
	if err != nil {
		return b.changed(err)
	}
	return nil
}
