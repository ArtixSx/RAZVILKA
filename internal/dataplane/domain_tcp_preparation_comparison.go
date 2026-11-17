package dataplane

import (
	"context"
	"errors"
)

type domainPreparationComparison uint8

const (
	domainPreparationPreflight domainPreparationComparison = iota
	domainPreparationClosing
)

// The fixed preflight body short-circuits its failed process opening before
// any baseline callback. Closing retains the original true wrapper: its eager
// Join cannot distinguish an opening failure from a later capture failure.
func (r *domainTCPCaptureExecutionResource) preparationComparisonBody(ctx context.Context, baseline *syntheticBaselineExecutionResource, files *xrayDomainTCPFileObservation, kind domainPreparationComparison) error {
	switch kind {
	case domainPreparationPreflight:
		view, err := r.readWithFiles(ctx, files)
		if err != nil {
			return err
		}
		for i := range r.effects.Effects {
			count, err := domainTCPCapturePresence(view.Rows, r.effects, i)
			if err != nil || count != 0 {
				return ErrDomainPolicyTCPConsumer
			}
		}
		return baseline.currentBaselineWithFiles(ctx, files)
	case domainPreparationClosing:
		return errors.Join(r.checkPreparedWithFiles(ctx, files), baseline.currentBaselineWithFiles(ctx, files))
	default:
		return ErrDomainPolicyTCPConsumer
	}
}

// Only Preflight and the post-Add pure closing call this comparison. Preflight
// supplies the SAME complete opening as the old wrapper; retain an independent
// full process closing after all callbacks, even when the body fails. Actual
// COMMON intent/Add/persist stays outside the revoked file/tool observations.
func (r *domainTCPCaptureExecutionResource) comparePreparation(ctx context.Context, baseline *syntheticBaselineExecutionResource, kind domainPreparationComparison) error {
	if kind != domainPreparationPreflight && kind != domainPreparationClosing {
		return ErrDomainPolicyTCPConsumer
	}
	return r.observeTools(ctx, func(observed context.Context) error {
		fallback := func() error {
			return r.observePreAddFiles(observed, true, func(files *xrayDomainTCPFileObservation) error {
				return r.preparationComparisonBody(observed, baseline, files, kind)
			})
		}
		if kind == domainPreparationClosing || observed == nil || observed.Value(domainTCPBaselineCleanupKey{}) != nil || observed.Value(domainTCPCaptureCleanupKey{}) != nil || observed.Value(domainTCPFailureCleanupKey{}) != nil {
			return fallback()
		}
		original, err := r.guardOriginalBaselineOwner(observed, baseline)
		if err != nil {
			return err
		}
		if !original {
			return fallback()
		}
		process, capture, mapping, tools, backend := r.process, r.capture, r.mapping, r.tools, r.backend
		material, binding, scope := process.material, process.material.binding, process.scope
		owner, originalOwner := capture.owner.(*DomainTCPOriginalScope)
		if !originalOwner || owner == nil {
			return ErrDomainPolicyTCPConsumer
		}
		source, backendRunner, toolRunner := owner.source, backend.reader.Runner, tools.Runner
		association := func() error {
			original, err := r.guardOriginalBaselineOwner(observed, baseline)
			if err != nil {
				return err
			}
			if !original || r.process != process || process.material != material || process.scope != scope || material.binding != binding || r.capture != capture || capture.owner != owner || r.mapping != mapping || r.tools != tools || r.backend != backend || !sameNetworkPolicyDependency(owner.source, source) || !sameNetworkPolicyDependency(backend.reader.Runner, backendRunner) || !sameNetworkPolicyDependency(tools.Runner, toolRunner) {
				return ErrDomainPolicyTCPConsumer
			}
			return nil
		}
		if err := association(); err != nil {
			return err
		}
		result := r.observePreAddFiles(observed, false, func(files *xrayDomainTCPFileObservation) error {
			result := r.preparationComparisonBody(observed, baseline, files, kind)
			return errors.Join(result, association(), process.currentWithFiles(observed, files), observed.Err())
		})
		return errors.Join(result, association(), observed.Err())
	})
}
