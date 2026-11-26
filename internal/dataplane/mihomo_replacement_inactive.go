package dataplane

import (
	"context"

	"github.com/ArtixSx/razvilka/internal/components"
)

type mihomoReplacementObservationKey struct{}
type mihomoReplacementObservation struct {
	adapter *MihomoProbeAdapter
	review  *components.MihomoReplacementReview
}

// VerifyMihomoReplacementInactive observes the complete original registry.
// The extra comparison belongs only to this exact Mihomo adapter and live
// component writer session. It exempts no process or another adapter.
func (m *Manager) VerifyMihomoReplacementInactive(ctx context.Context, adapter *MihomoProbeAdapter, review *components.MihomoReplacementReview) error {
	if m == nil || ctx == nil || adapter == nil || review == nil || !adapter.RegisteredWith(m) || !review.OwnedBy(adapter.components) {
		return ErrRuntimeInactivity
	}
	if err := review.Current(ctx); err != nil {
		return err
	}
	held := context.WithValue(ctx, mihomoReplacementObservationKey{}, mihomoReplacementObservation{adapter, review})
	if err := m.VerifyRuntimeInactive(held); err != nil {
		return err
	}
	if !adapter.RegisteredWith(m) || !review.OwnedBy(adapter.components) {
		return ErrRuntimeInactivity
	}
	return review.Current(ctx)
}

func (a *MihomoProbeAdapter) replacementObservation(ctx context.Context) (*components.MihomoReplacementReview, error) {
	value, ok := ctx.Value(mihomoReplacementObservationKey{}).(mihomoReplacementObservation)
	if !ok || value.adapter != a {
		return nil, nil
	}
	if value.review == nil || !value.review.OwnedBy(a.components) {
		return nil, ErrRuntimeInactivity
	}
	return value.review, value.review.Current(ctx)
}
