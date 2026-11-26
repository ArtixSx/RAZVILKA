package defaultconsent

import (
	"context"
	"reflect"

	"github.com/ArtixSx/razvilka/internal/config"
)

// AcceptAutonomyCommitted advances only this same original scope review from
// an actual single-service Store writer receipt. It grants no node/path proof
// or renewed approval. Physical continuity remains with the retained App owner.
func (s *ScopeReview) AcceptAutonomyCommitted(ctx context.Context, commit *config.AutonomyRouteCommitReview) error {
	return s.acceptAutonomyTransition(ctx, commit, false)
}

// AcceptAutonomyRestored consumes the original writer's actual successful undo;
// an arbitrary restored config tuple cannot supply that producer. Undo restores
// the exact preimage, including its original revision and application time.
func (s *ScopeReview) AcceptAutonomyRestored(ctx context.Context, commit *config.AutonomyRouteCommitReview) error {
	return s.acceptAutonomyTransition(ctx, commit, true)
}

func (s *ScopeReview) acceptAutonomyTransition(ctx context.Context, commit *config.AutonomyRouteCommitReview, restored bool) error {
	err := s.withReview(func(r *Review) error { return r.acceptAutonomyTransition(ctx, commit, restored) })
	if err != nil && s != nil && s.self == s {
		s.autonomyInvalid.Store(true)
	}
	return err
}

func (r *Review) acceptAutonomyTransition(ctx context.Context, commit *config.AutonomyRouteCommitReview, restored bool) error {
	if r == nil || r.self != r || r.owner == nil || !r.scopeOnly || r.ref.NodeID != "" || !commit.MatchesStore(r.owner.store) {
		return ErrChanged
	}
	return r.owner.withOwner(ctx, func() error {
		read := commit.CommittedImages
		if restored {
			read = commit.RestoredImages
		}
		before, after, err := read(ctx)
		if err != nil || !reflect.DeepEqual(r.expectedConfig(), before) || !config.CurrentDefaultRouteScopeConsent(after) || after.SafeMode || after.ServiceControl.Stopped ||
			after.DefaultRouteConsent == nil || after.DefaultRouteConsent.Digest != r.ref.ConsentDigest || after.DefaultRouteConsent.ApprovalRevision != r.ref.ApprovalRevision ||
			!reflect.DeepEqual(before.NetworkPolicy, after.NetworkPolicy) || !reflect.DeepEqual(before.DefaultRouteConsent, after.DefaultRouteConsent) {
			return ErrChanged
		}
		if err := r.owner.control.Current(ctx); err != nil {
			return err
		}
		closingBefore, closingAfter, err := read(ctx)
		if err != nil || !reflect.DeepEqual(before, closingBefore) || !reflect.DeepEqual(after, closingAfter) {
			return ErrChanged
		}
		if err := r.owner.control.Current(ctx); err != nil {
			return err
		}
		r.cfgMu.Lock()
		defer r.cfgMu.Unlock()
		if !reflect.DeepEqual(r.cfg, before) {
			return ErrChanged
		}
		r.cfg = after // Detached clone from the actual sealed Store receipt.
		return nil
	})
}
