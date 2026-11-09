package dataplane

import (
	"context"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/dnscontrol"
	"github.com/ArtixSx/razvilka/internal/operationgate"
)

// Refusal models only. These inert ledger/process handles cannot issue a
// preparation token, native owner or cleanup grant. Native success is tested
// separately after the actual capture-prepared producer cut.
func TestDomainFailureUnpublishedPreparationRejectsForeignComparison(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	o := &DomainTCPOriginalScope{}
	o.self = o
	c := &domainTCPGlobalSuccessor{}
	p := &XrayDomainTCPExecutionResource{scope: &executionResourceScope{domainSuccessor: c}}
	p.self = p
	control := &operationgate.ControlEpochReview{}
	source := &dnscontrol.NetworkPolicyDNSSyntheticResolver{}
	p.material = &XrayDomainTCPOperationMaterial{control: control, dnsSource: source}
	capture := &domainTCPCaptureExecutionResource{process: p, retirementDetached: true}
	capture.self = capture
	r := &domainTCPFailureCleanup{cursor: c, resource: p, capture: capture}
	r.self = r
	closed := &dnscontrol.SyntheticDNSRetirementReview{}
	inspector := &syntheticBaselineKernelInspector{}
	inspector.self = inspector
	baseline := &syntheticBaselineExecutionResource{retirement: closed, inspector: inspector}
	u := &domainTCPUnpublishedPreparation{owner: o, cursor: r, process: p, capture: capture, baseline: baseline, closed: closed, source: source, control: control}
	u.self = u
	o.unpublishedPreparation = u
	for _, mode := range []string{"copied", "foreign-owner", "foreign-source", "foreign-control", "foreign-ledger", "possibly-issued", "foreign-cursor", "no-native-ledger"} {
		t.Run(mode, func(t *testing.T) {
			call, owner := *u, o
			call.self = &call
			switch mode {
			case "copied":
				call.self = u
			case "foreign-owner":
				owner = &DomainTCPOriginalScope{}
			case "foreign-source":
				call.source = &dnscontrol.NetworkPolicyDNSSyntheticResolver{}
			case "foreign-control":
				call.control = &operationgate.ControlEpochReview{}
			case "foreign-ledger":
				call.closed = &dnscontrol.SyntheticDNSRetirementReview{}
			case "possibly-issued":
				call.row.PossiblyIssued = true
			case "foreign-cursor":
				call.cursor = &domainTCPFailureCleanup{self: r}
			}
			o.unpublishedPreparation = &call
			if call.current(ctx, owner) == nil {
				t.Fatal("comparison manufactured an unpublished preparation")
			}
		})
	}
	o.unpublishedPreparation = u
	// Even the exact private shape has neither a genuine joined child/source
	// nor original capture/COMMON readbacks and therefore cannot be positive.
	if u.current(ctx, o) == nil {
		t.Fatal("inert original shape acquired native preparation")
	}
}

func TestDomainFailureUnpublishedPreparationRejectsAnyFlowIssuer(t *testing.T) {
	s := &executionResourceScope{execution: &Execution{}}
	if !unpublishedDomainNoFlowLocked(s) {
		t.Fatal("empty comparison shape refused")
	}
	s.domainTCPBaselines = map[string]*domainTCPBaselineExecutionResource{"original": {}}
	if unpublishedDomainNoFlowLocked(s) {
		t.Fatal("original live issuer ignored")
	}
	s.domainTCPBaselines = nil
	for _, row := range []ExecutionResource{
		{Kind: "domain-tcp-baseline-flow", State: "removed"},
		{Kind: "foreign-kind", DomainTCPBaseline: &ExecutionDomainTCPBaselineDefinition{}},
	} {
		s.execution.Resources = []ExecutionResource{row}
		if unpublishedDomainNoFlowLocked(s) {
			t.Fatal("baseline-flow row ignored with empty map")
		}
	}
}
