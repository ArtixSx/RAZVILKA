package strategylab

import (
	"context"
	"errors"

	"github.com/ArtixSx/razvilka/internal/components"
)

// Only the already-running original canary's hardcoded material reader uses
// this comparison. Environment, guard, WAN and socket callbacks remain outside
// it. Initial selection/validation and every other reader retain full Checks.
func (r *SelectedCandidateReview) materialReadCurrentLocked(ctx context.Context) error {
	if r == nil || !r.canary || r.probe == nil || r.probe.self != r.probe || r.probe.source == nil || r.probe.source.material != r || r.probe.manager != r.binding.manager || r.runtime == nil || r.provider == nil || r.provider.self != r.provider || r.provider.managedControl == nil {
		return r.materialCurrentWithRuntimeReadLocked(ctx, nil)
	}
	lease, probe, source, provider, manager := r.runtime, r.probe, r.probe.source, r.provider, r.binding.manager
	current := func() bool {
		return r.runtime == lease && r.probe == probe && probe.source == source && source.material == r && r.provider == provider && r.binding.manager == manager && r.canary
	}
	began, err := lease.WithReadObservation(ctx, func(observed context.Context, view *components.ManagedNFQWSRuntimeRead) error {
		if !current() || !view.BoundTo(lease) {
			return ErrSelectedCandidateChanged
		}
		result := r.materialCurrentWithRuntimeReadLocked(observed, view)
		if !current() {
			return errors.Join(result, ErrSelectedCandidateChanged)
		}
		return result
	})
	if !began {
		return r.materialCurrentWithRuntimeReadLocked(ctx, nil)
	}
	if !current() {
		return errors.Join(err, ErrSelectedCandidateChanged)
	}
	return err
}

func (r *SelectedCandidateReview) materialRuntimeCompare(ctx context.Context, view *components.ManagedNFQWSRuntimeRead) error {
	if view == nil {
		return r.runtime.Check(ctx)
	}
	if !view.BoundTo(r.runtime) {
		return ErrSelectedCandidateChanged
	}
	return view.CompareCurrent(ctx)
}
