package dataplane

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestDomainPreparationComparisonInvalidEntryCannotReachBody(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	for _, kind := range []domainPreparationComparison{domainPreparationPreflight, domainPreparationClosing, 255} {
		for _, resource := range []*domainTCPCaptureExecutionResource{nil, {}, {process: &XrayDomainTCPExecutionResource{}}} {
			if resource != nil {
				resource.self = resource
			}
			// If the later eager closing body were reached with this nil
			// baseline, it would panic instead of refusing the invalid producer.
			if err := resource.comparePreparation(ctx, nil, kind); !errors.Is(err, ErrDomainPolicyTCPConsumer) {
				t.Fatal("invalid entry reached preparation", kind, err)
			}
		}
	}
}

func TestDomainPreparationComparisonKeepsShortCircuitAndEagerClosing(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	var capture *domainTCPCaptureExecutionResource
	baseline := &syntheticBaselineExecutionResource{}
	baseline.self = baseline
	// First source refusal remains the preflight result: the baseline's
	// separate failure must not be evaluated or replace that first exception.
	err := capture.preparationComparisonBody(ctx, baseline, nil, domainPreparationPreflight)
	if !errors.Is(err, ErrDomainPolicyTCPConsumer) || errors.Is(err, ErrSyntheticBaselineTransition) {
		t.Fatal("preflight short-circuit changed", err)
	}
	// The post-Add body intentionally evaluates BOTH comparisons, as the old
	// errors.Join did. Failure of the capture must not hide baseline failure.
	err = capture.preparationComparisonBody(ctx, baseline, nil, domainPreparationClosing)
	if !errors.Is(err, ErrDomainPolicyTCPConsumer) || !errors.Is(err, ErrSyntheticBaselineTransition) {
		t.Fatal("closing lost one independent failure", err)
	}
	if err := capture.preparationComparisonBody(ctx, nil, nil, 255); !errors.Is(err, ErrDomainPolicyTCPConsumer) {
		t.Fatal("unknown comparison kind ran a body", err)
	}
}

func TestDomainPreparationComparisonDoesNotTurnStaticAssociationsIntoCurrent(t *testing.T) {
	f, kernel, runner := baselineCurrentComparison(t)
	for _, kind := range []domainPreparationComparison{domainPreparationPreflight, domainPreparationClosing} {
		if err := kernel.capture.comparePreparation(f.ctx, kernel.baseline, kind); err == nil {
			t.Fatal("static tuple minted original preparation")
		}
		if runner.calls != 0 {
			t.Fatal("invalid original tuple reached external callback", runner.calls)
		}
	}
}
