package strategylab

import (
	"context"
	"errors"
	"slices"
	"time"

	"github.com/ArtixSx/razvilka/internal/operationgate"
)

// InstallManagedCompatibilityValidator changes only this configured source
// owner's validator slot, under its lock. It starts no phase, rewrites no source
// and grants no native/scope/runtime permission. Each later validation still
// acquires the real current component lease and original operation admission.
// The existing actual inactive review must span the genuine bundle install.
// Successful handover invalidates that old review and all old source reviews.
func (m *Manager) InstallManagedCompatibilityValidator(ctx context.Context, control *operationgate.ControlEpochReview, provider *SupervisedCompatibilityProvider, validator CompatibleValidator, inactive *ManagedCompatibilityInactiveReview) error {
	if m == nil || selectedReviewContext(ctx) != nil || control == nil || inactive == nil || inactive.self != inactive || inactive.manager != m || inactive.control != control || !managedCompatibilityValidatorMatches(m, control, provider, validator) {
		return errAdaptiveManagedValidator
	}
	if err := inactive.Current(ctx); err != nil {
		return err
	}
	inactive.mu.Lock()
	defer inactive.mu.Unlock()
	if inactive.closed || inactive.cleanup == nil {
		return ErrCompatibilityQuiescenceUnknown
	}
	return inactive.cleanup.WithCurrent(ctx, func() error {
		if err := control.Current(ctx); err != nil {
			return err
		}
		m.mu.Lock()
		defer m.mu.Unlock()
		if err := inactive.sourceCurrentLocked(ctx); err != nil {
			return err
		}
		provider.mu.Lock()
		defer provider.mu.Unlock()
		if provider == inactive.provider || provider.running || provider.unknown || provider.session != nil || provider.managedInvocation != nil || provider.managedRetiredSession != nil || !managedCompatibilityValidatorMatches(m, control, provider, validator) {
			return errAdaptiveManagedValidator
		}
		if err := errors.Join(compatibilityProtectedReview(m.Path, provider.review), compatibilityFilesUnchanged(provider.review), selectedReviewMaterial(provider.review, provider.managedDescriptor)); err != nil {
			return err
		}
		if err := errors.Join(inactive.imageCurrentLocked(ctx), control.Current(ctx)); err != nil {
			return err
		}
		previous := m.Validator
		validator.BaseArguments = slices.Clone(validator.BaseArguments)
		m.Validator = validator
		if err := errors.Join(inactive.imageCurrentLocked(ctx), control.Current(ctx)); err != nil {
			// No native effect or source write occurred. Restore only this
			// in-memory slot while still holding the original source lock.
			m.Validator = previous
			return err
		}
		return nil
	})
}

// Exact constructor shape comparison only; it cannot issue a provider, lease,
// original operation or source review from a caller's declaration.
func managedCompatibilityValidatorMatches(m *Manager, control *operationgate.ControlEpochReview, p *SupervisedCompatibilityProvider, v CompatibleValidator) bool {
	return p != nil && p.self == p && p.manager == m && control != nil && p.managedControl == control &&
		v.Provider == p && v.TrustedAssets && v.Binary == p.review.Binary.Path && v.Timeout == 8*time.Second && slices.Equal(v.BaseArguments, p.review.BaseArguments) &&
		validateCompatibilityReview(p.review) == nil && control.MatchesControlRoot(p.review.ControlPath) && selectedReviewMaterial(p.review, p.managedDescriptor) == nil
}
