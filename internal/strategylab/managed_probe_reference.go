package strategylab

import (
	"context"
	"errors"
	"reflect"
	"slices"

	"github.com/ArtixSx/razvilka/internal/components"
	"github.com/ArtixSx/razvilka/internal/operationgate"
)

// WithProbeReferenceCurrent brackets a read-only observation with fresh actual
// source, environment and active-slot checks. The detached comparison value is
// never a process owner, cache, new context or reusable Start grant. No source
// or epoch lock is held across either the read or environment callbacks.
func (r *ManagedProbeEpoch) WithProbeReferenceCurrent(ctx context.Context, source *CandidateProbeReview, runtime *components.ManagedNFQWSRuntimeLease, control *operationgate.ControlEpochReview, read func(CandidateProbeReference) error) error {
	if r == nil || r.self != r || source == nil || r.source != source || r.manager == nil || r.environment == nil || read == nil || selectedReviewContext(ctx) != nil {
		return errors.Join(ErrSelectedCandidateChanged, selectedReviewContext(ctx))
	}
	source.mu.Lock()
	matchingOwners := source.self == source && !source.closed && source.material != nil && source.material.binding.manager == r.manager && runtime != nil && control != nil && source.material.runtime == runtime && source.material.provider != nil && source.material.provider.managedControl == control
	source.mu.Unlock()
	if !matchingOwners {
		return ErrSelectedCandidateChanged
	}
	active := func() bool {
		r.mu.Lock()
		running := r.running && !r.complete && !r.failed
		r.mu.Unlock()
		r.manager.mu.Lock()
		owned := r.manager.managedProbe == r && r.manager.nativeRunning && !r.manager.compatibilityUnknownLocked() && !r.manager.writeBlocked
		r.manager.mu.Unlock()
		return running && owned
	}
	if !active() {
		return ErrSelectedCandidateChanged
	}
	if err := r.environment.Current(ctx); err != nil {
		return err
	}
	reference, err := source.managedProbeReferencePhase(ctx, runtime, control)
	if err != nil {
		return err
	}
	record := r.record // Immutable after BeginManagedProbe returns this owner.
	if reference.Material.CandidateID != record.CandidateID || reference.Material.Incarnation != record.Incarnation || reference.ValidationGeneration != record.ValidationGeneration || reference.Scope.Target.ServiceID != record.ServiceID || reference.Scope.CriteriaDigest != record.CriteriaDigest || reference.Scope.Address.String() != record.PinnedAddress || record.Scope != "router-output-https-tcp443-ipv4" || reference.Scope.Target.Protocol != "tcp" || reference.Scope.Target.IPFamily != "ipv4" {
		return ErrSelectedCandidateChanged
	}
	copy := reference
	copy.Material.Arguments = slices.Clone(reference.Material.Arguments)
	copy.Material.Traffic = slices.Clone(reference.Material.Traffic)
	readErr := read(copy)
	environmentErr := r.environment.Current(ctx)
	closing, closingErr := source.managedProbeReferencePhase(ctx, runtime, control)
	if closingErr == nil && !reflect.DeepEqual(reference, closing) {
		closingErr = ErrSelectedCandidateChanged
	}
	if !active() {
		closingErr = errors.Join(ErrSelectedCandidateChanged, closingErr)
	}
	return errors.Join(readErr, environmentErr, closingErr, ctx.Err())
}

// One phase of the enclosing observation bracket. No callback can occur
// between the complete material check and the immutable reference derivation.
// The other complete phase MUST remain after the external read/environment.
// Public Reference/ManagedReference retain their independent full brackets.
func (r *CandidateProbeReview) managedProbeReferencePhase(ctx context.Context, runtime *components.ManagedNFQWSRuntimeLease, control *operationgate.ControlEpochReview) (reference CandidateProbeReference, result error) {
	if r == nil || r.self != r || selectedReviewContext(ctx) != nil {
		return reference, errors.Join(ErrSelectedCandidateChanged, selectedReviewContext(ctx))
	}
	r.mu.Lock()
	if r.closed || r.material == nil {
		r.mu.Unlock()
		return reference, ErrSelectedCandidateChanged
	}
	priorEpoch := r.material.managedEpoch
	r.mu.Unlock()
	if priorEpoch != nil {
		if err := priorEpoch.Current(ctx); err != nil {
			return reference, err
		}
		// Registered before locks: closing Current runs only after both unlocks.
		defer func() { result = errors.Join(result, priorEpoch.Current(ctx)) }()
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || r.material == nil || r.material.managedEpoch != priorEpoch || runtime == nil || control == nil || r.material.runtime != runtime || r.material.provider == nil || r.material.provider.managedControl != control || r.material.binding.manager == nil {
		return reference, ErrSelectedCandidateChanged
	}
	m := r.material.binding.manager
	m.mu.RLock()
	defer m.mu.RUnlock()
	if err := r.material.materialCurrentLocked(ctx); err != nil {
		return reference, err
	}
	return r.referenceLocked()
}
