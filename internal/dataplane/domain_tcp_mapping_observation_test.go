package dataplane

import (
	"context"
	"testing"

	"github.com/ArtixSx/razvilka/internal/dnscontrol"
)

func mappingReadSourcesFixture(t *testing.T) (*domainCaptureReadComparisonFixture, *domainTCPBaselineKernelOwner, *baselineCurrentComparisonRunner, *domainTCPMappingReadSources) {
	f, kernel, runner := baselineCurrentComparison(t)
	prepared := &DomainPolicyTCPCaptureMapping{capture: f.capture, source: kernel.capture.mapping}
	prepared.self = prepared
	f.owner.prepared = prepared
	baseline, original, err := kernel.originalCurrentSources(f.ctx)
	if err != nil || !original {
		t.Fatal(err)
	}
	s := &domainTCPMappingReadSources{baseline: baseline, kernel: kernel, prepared: prepared}
	if err := s.current(f.ctx, f.owner, f.process, kernel.capture.mapping); err != nil {
		t.Fatal(err)
	}
	return f, kernel, runner, s
}

func TestDomainMappingObservationOriginalAssociations(t *testing.T) {
	for _, mode := range []string{"prepared-copy", "prepared-owner", "prepared-capture", "prepared-source", "mapping", "owner", "process", "source", "scope", "canceled"} {
		t.Run(mode, func(t *testing.T) {
			f, kernel, runner, s := mappingReadSourcesFixture(t)
			owner, process, mapping := f.owner, f.process, kernel.capture.mapping
			switch mode {
			case "prepared-copy":
				s.prepared.self = &DomainPolicyTCPCaptureMapping{}
			case "prepared-owner":
				f.owner.prepared = &DomainPolicyTCPCaptureMapping{}
			case "prepared-capture":
				s.prepared.capture = &DomainPolicyTCPCapture{}
			case "prepared-source":
				s.prepared.source = &dnscontrol.SyntheticDNSMapping{}
			case "mapping":
				mapping = &dnscontrol.SyntheticDNSMapping{}
			case "owner":
				owner = &DomainTCPOriginalScope{}
			case "process":
				process = &XrayDomainTCPExecutionResource{}
			case "source":
				f.owner.source = &baselineCurrentComparisonRunner{}
			case "scope":
				f.process.scope = &executionResourceScope{}
			case "canceled":
				f.cancel()
			}
			if s.current(f.ctx, owner, process, mapping) == nil {
				t.Fatal("changed association accepted", mode)
			}
			if runner.calls != 0 {
				t.Fatal("local comparison reached external source")
			}
		})
	}
}

func TestDomainMappingObservationCannotMintCurrent(t *testing.T) {
	f, kernel, runner, _ := mappingReadSourcesFixture(t)
	if err := f.owner.compareMappingInOriginalToolObservation(f.ctx, f.process, kernel.capture.mapping); err == nil {
		t.Fatal("static comparison issued live Current")
	}
	if runner.calls != 0 {
		t.Fatal("unowned process reached external tool callback")
	}
}

func TestDomainMappingObservationPreservesCleanupAndCustomRefusal(t *testing.T) {
	for _, mode := range []string{"baseline-cleanup", "capture-cleanup", "failure-cleanup", "custom-source", "missing-kernel"} {
		t.Run(mode, func(t *testing.T) {
			f, kernel, runner, _ := mappingReadSourcesFixture(t)
			ctx := f.ctx
			switch mode {
			case "baseline-cleanup":
				ctx = context.WithValue(ctx, domainTCPBaselineCleanupKey{}, "foreign")
			case "capture-cleanup":
				ctx = context.WithValue(ctx, domainTCPCaptureCleanupKey{}, "foreign")
			case "failure-cleanup":
				ctx = context.WithValue(ctx, domainTCPFailureCleanupKey{}, "foreign")
			case "custom-source":
				kernel.capture.backend.reader.Runner = &baselineCurrentUnobservedRunner{}
			case "missing-kernel":
				f.owner.kernel = nil
			}
			mapping := kernel.capture.mapping
			before := f.process.withCurrentFileObservation(ctx, func(files *xrayDomainTCPFileObservation) error {
				return f.owner.compareSyntheticMappingWithFiles(ctx, mapping, files)
			})
			after := f.owner.compareMappingInOriginalToolObservation(ctx, f.process, mapping)
			if before == nil || after == nil || before.Error() != after.Error() || runner.calls != 0 {
				t.Fatal("original refusal changed", before, after)
			}
		})
	}
}
