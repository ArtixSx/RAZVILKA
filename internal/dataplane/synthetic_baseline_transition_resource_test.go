package dataplane

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/netidentity"
)

func TestSyntheticBaselineResourceIntentClonesAndValidatesWithoutRuntimeGrant(t *testing.T) {
	_, _, plan, scope, _ := syntheticExecutionModel(t)
	d := &ExecutionSyntheticBaselineDefinition{Schema: 1, PlanID: plan.PlanID, PlanDigest: plan.Digest, DomainDigest: plan.DomainPolicy.Digest, NetworkIdentity: scope.networkIdentity.value}
	d.Mapping.Authority.Generation = plan.DomainPolicy.Generation
	d.Mapping.Authority.ControlEpoch = 1
	d.Mapping.Authority.BindingRevision = 1
	d.Mapping.Authority.Exclusions = plan.SyntheticDNS.DNS.Exclusions
	d.Mapping.PublicationID = strings.Repeat("b", 32)
	d.Mapping.Client = plan.SyntheticDNS.Definition.Client
	d.Mapping.DeviceID = plan.SyntheticDNS.Definition.DeviceID
	d.Mapping.MAC = plan.SyntheticDNS.Definition.MAC
	d.Mapping.Ingress = plan.SyntheticDNS.Definition.Ingress
	d.Mapping.QName = plan.SyntheticDNS.Definition.ExactNames[0]
	d.Mapping.Synthetic = domainPolicyTCPSyntheticPool.Addr().Next()
	d.Mapping.RealIPv4 = netip.MustParseAddr("93.184.215.14")
	d.Mapping.ExpiresAt = time.Unix(200, 0)
	d.Mapping.CNAMEChain = []string{"alias.example.com"}
	compiled, err := syntheticBaselineDefinitionEffects(d)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := PolicyEffectPlanDigest(compiled)
	if err != nil {
		t.Fatal(err)
	}
	record := ExecutionResource{Kind: "synthetic-baseline", State: "prepared", Phase: "baseline-prepared", Generation: compiled.Generation, EffectsDigest: digest}
	execution := Execution{PlanID: plan.PlanID, Digest: plan.Digest}
	if err := validateExecutionSyntheticBaselineResource(execution, record, d); err != nil {
		t.Fatal(err)
	}
	copy := cloneExecutionSyntheticBaselineDefinition(d)
	copy.Mapping.CNAMEChain[0] = "changed.example.com"
	if d.Mapping.CNAMEChain[0] != "alias.example.com" {
		t.Fatal("metadata clone changed original")
	}
	for _, mutation := range []func(*ExecutionSyntheticBaselineDefinition){
		func(x *ExecutionSyntheticBaselineDefinition) { x.NetworkIdentity = netidentity.Identity{} },
		func(x *ExecutionSyntheticBaselineDefinition) { x.PlanDigest = strings.Repeat("e", 64) },
		func(x *ExecutionSyntheticBaselineDefinition) { x.Mapping.PublicationID = "not-hex" },
		func(x *ExecutionSyntheticBaselineDefinition) { x.Mapping.LastPossiblyIssuedTTLBound = 5 },
		func(x *ExecutionSyntheticBaselineDefinition) {
			x.Mapping.RealIPv4 = domainPolicyTCPSyntheticPool.Addr()
		},
	} {
		bad := cloneExecutionSyntheticBaselineDefinition(d)
		mutation(bad)
		if err := validateExecutionSyntheticBaselineResource(execution, record, bad); err == nil {
			t.Fatal("malformed typed resource accepted")
		}
	}
	for _, phase := range []string{"ready", "active", "removed"} {
		bad := record
		bad.Phase = phase
		if err := validateExecutionSyntheticBaselineResource(execution, bad, d); err == nil {
			t.Fatal("phase/state substitution accepted", phase)
		}
	}
}

func TestSyntheticBaselineReceiptAllowanceRequiresOriginalBorrowAndOrderedACKs(t *testing.T) {
	plan, _ := syntheticBaselineKernelModel(t)
	rows, required, err := syntheticBaselineReceiptRows(plan, []string{"added", "added", "added", "added"}, false)
	if err != nil || len(rows) != 4 || len(required) != 4 {
		t.Fatal("complete receipt shape refused", err)
	}
	for _, value := range required {
		if !value {
			t.Fatal("actual ACK row made optional")
		}
	}
	rows, required, err = syntheticBaselineReceiptRows(plan, []string{"added", "intent", "planned", "planned"}, true)
	if err != nil || len(rows) != 2 || !required[0] || required[1] {
		t.Fatal("borrowed original partial shape changed", err)
	}
	for _, states := range [][]string{{"added", "intent", "planned", "planned"}, {"added", "planned", "added", "planned"}, {"added", "intent", "intent", "planned"}, {"added", "added", "cleanup-intent", "removed"}} {
		if _, _, err := syntheticBaselineReceiptRows(plan, states, false); err == nil {
			t.Fatal("unborrowed/pending cleanup became allowance", states)
		}
	}
	if _, _, err := syntheticBaselineReceiptRows(plan, []string{"added", "planned", "added", "planned"}, true); err == nil {
		t.Fatal("unordered receipt ACK accepted")
	}
}
