package dataplane

import (
	"context"
	"net/netip"
	"strings"
	"testing"
)

func TestDomainTCPBaselineRetainedIntentNeverBecomesActive(t *testing.T) {
	process := xrayDomainExecutionDefinitionFixture(t)
	d := ExecutionDomainTCPBaselineDefinition{Schema: 1, Capture: ExecutionDomainTCPCaptureDefinition{Schema: 1, Process: process}, Source: netip.AddrPortFrom(process.Capture.Client.Address, 49123), Target: netip.AddrPortFrom(process.Capture.Xray.RealIP, 443), Egress: "wan0"}
	p, err := compileDomainTCPBaselineFlow(d.flowSpec())
	if err != nil {
		t.Fatal(err)
	}
	digest, _ := PolicyEffectPlanDigest(p)
	r := ExecutionResource{ID: "bf-" + strings.Repeat("a", 32), Kind: "domain-tcp-baseline-flow", State: "prepared", Phase: "planned", Generation: p.Generation, EffectsDigest: digest, DomainTCPBaseline: &d}
	e := Execution{PlanID: process.PlanID, Digest: process.PlanDigest, State: "checking", Resources: []ExecutionResource{r}}
	if err := validateExecutionResources(e, false); err != nil {
		t.Fatal(err)
	}
	if err := validateExecutionResources(e, true); err == nil {
		t.Fatal("planned retained intent became settled")
	}
	if !executionHasNetworkIdentity(e) {
		t.Fatal("new typed history lost required original network identity")
	}
	for _, phase := range []string{"prepared", "connected", "closed"} {
		x := r
		x.Phase = phase
		e.Resources = []ExecutionResource{x}
		if validateExecutionResources(e, false) != nil || validateExecutionResources(e, true) == nil {
			t.Fatal("pending lifecycle classified terminal", phase)
		}
	}
	for _, state := range []string{"removed", "unused"} {
		x := r
		x.Phase = state
		x.State = state
		e.Resources = []ExecutionResource{x}
		if err := validateExecutionResources(e, true); err != nil {
			t.Fatal(state, err)
		}
	}
	x := r
	x.State = "active"
	x.Phase = "active"
	e.Resources = []ExecutionResource{x}
	if validateExecutionResources(e, false) == nil {
		t.Fatal("metadata manufactured ACTIVE")
	}
	e.Resources = []ExecutionResource{r}
	clone := cloneExecutionResources(e.Resources)
	clone[0].DomainTCPBaseline.Capture.Process.Domain.Services[0].ID = "changed"
	if e.Resources[0].DomainTCPBaseline.Capture.Process.Domain.Services[0].ID == "changed" {
		t.Fatal("retained definition alias escaped clone")
	}
}

func TestDomainTCPBaselineTupleAndCallbacksCannotIssueOriginalFD(t *testing.T) {
	kernel := &domainTCPBaselineKernelOwner{capture: &domainTCPCaptureExecutionResource{capture: &DomainPolicyTCPCapture{}}}
	kernel.self = kernel
	if r, err := issueDomainTCPBaselineFlow(context.Background(), kernel, DomainPolicyTCPSocket{}); err == nil || r != nil {
		t.Fatal("tuple without original accepted FD issued intent")
	}
	if _, err := (&domainTCPBaselineExecutionResource{}).connectNative(context.Background()); err == nil {
		t.Fatal("empty retained definition became a native dial")
	}
}
