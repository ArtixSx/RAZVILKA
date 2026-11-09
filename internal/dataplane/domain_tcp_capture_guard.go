package dataplane

import (
	"context"
	"errors"
)

// This closed comparison alone may share its opening process observation.
// registered performs only concrete local/held-owner reads, then currentWithFiles
// checks the full original process BEFORE its first mapping/runner callback.
// No positive observation is retained across this synchronous guard or an Add.
func (r *domainTCPCaptureExecutionResource) guardOriginalBaseline(ctx context.Context, baseline *syntheticBaselineExecutionResource) error {
	if err := r.local(ctx); err != nil {
		return err
	}
	return r.observeTools(ctx, func(observed context.Context) error {
		original, err := r.guardOriginalBaselineOwner(observed, baseline)
		if err != nil {
			return err
		}
		if !original {
			// Existing custom producers retain their complete original wrapper.
			return r.observePreAddFiles(observed, true, func(files *xrayDomainTCPFileObservation) error {
				return errors.Join(r.currentWithFiles(observed, files), baseline.currentBaselineWithFiles(observed, files))
			})
		}
		defer domainTCPMeasure("capture-guard-original-opening")(0)
		return r.observePreAddFiles(observed, false, func(files *xrayDomainTCPFileObservation) error {
			// This is the same full opening as inside the old wrapper. Its
			// refusal must precede every later baseline callback and effect.
			if err := r.currentWithFiles(observed, files); err != nil {
				return errors.Join(err, r.process.currentWithFiles(observed, files), observed.Err())
			}
			result := baseline.currentBaselineWithFiles(observed, files)
			closingOriginal, ownerErr := r.guardOriginalBaselineOwner(observed, baseline)
			if !closingOriginal {
				ownerErr = errors.Join(ownerErr, ErrDomainPolicyTCPConsumer)
			}
			// Keep the independent FULL closing after ALL baseline callbacks,
			// even when one failed. The outer scope still closes complete SHA.
			result = errors.Join(result, ownerErr, r.process.currentWithFiles(observed, files), observed.Err())
			if result == nil {
				domainTCPMeasure("capture-guard-original-closing")(0)
			}
			return result
		})
	})
}

func (r *domainTCPCaptureExecutionResource) guardOriginalBaselineOwner(ctx context.Context, baseline *syntheticBaselineExecutionResource) (bool, error) {
	if err := r.local(ctx); err != nil {
		return false, err
	}
	owner, original := r.capture.owner.(*DomainTCPOriginalScope)
	if !original {
		return false, nil
	}
	if _, supported := r.backend.reader.Runner.(domainTCPToolObserver); !supported {
		return false, nil
	}
	if owner == nil || owner.self != owner || baseline == nil || baseline.self != baseline ||
		baseline.capture != r.capture || baseline.binding != r.process.material.binding ||
		baseline.mapping != r.mapping || baseline.tools != r.tools || baseline.backend != r.backend {
		return false, ErrDomainPolicyTCPConsumer
	}
	owner.mu.Lock()
	same := !owner.closed && owner.process == r.process && owner.capture == r.capture &&
		owner.captureResource == r && owner.baseline == baseline && owner.binding == baseline.binding
	owner.mu.Unlock()
	if !same {
		return false, ErrDomainPolicyTCPConsumer
	}
	return true, nil
}
