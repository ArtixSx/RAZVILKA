package dataplane

import (
	"context"
	"github.com/ArtixSx/razvilka/internal/components"
)

type hevReplacementObservationKey struct{}
type hevReplacementObservation struct {
	adapter *MihomoProbeAdapter
	review  *components.HEVReplacementReview
}

// VerifyHEVReplacementInactive retains the complete original registry and
// adds old/desired HEV-byte recognition only for this exact original adapter.
// No process, socket, retained transaction or another adapter is exempted.
func (m *Manager) VerifyHEVReplacementInactive(ctx context.Context, adapter *MihomoProbeAdapter, review *components.HEVReplacementReview) error {
	if m == nil || ctx == nil || adapter == nil || review == nil || !adapter.RegisteredWith(m) || !review.OwnedBy(adapter.components) {
		return ErrRuntimeInactivity
	}
	if ctx.Value(mihomoReplacementObservationKey{}) != nil || ctx.Value(hevReplacementObservationKey{}) != nil {
		return ErrRuntimeInactivity
	}
	if err := review.Current(ctx); err != nil {
		return err
	}
	held := context.WithValue(ctx, hevReplacementObservationKey{}, hevReplacementObservation{adapter, review})
	if err := m.VerifyRuntimeInactive(held); err != nil {
		return err
	}
	if !adapter.RegisteredWith(m) || !review.OwnedBy(adapter.components) {
		return ErrRuntimeInactivity
	}
	return review.Current(ctx)
}
func (a *MihomoProbeAdapter) hevReplacementObservation(ctx context.Context) (*components.HEVReplacementReview, error) {
	value, ok := ctx.Value(hevReplacementObservationKey{}).(hevReplacementObservation)
	if !ok || value.adapter != a {
		return nil, nil
	}
	if ctx.Value(mihomoReplacementObservationKey{}) != nil || value.review == nil || !value.review.OwnedBy(a.components) {
		return nil, ErrRuntimeInactivity
	}
	return value.review, value.review.Current(ctx)
}
