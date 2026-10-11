package dataplane

import (
	"strings"
	"testing"
)

func TestExecutionResourceRejectsSyntheticDefinitionOnValidXrayRecord(t *testing.T) {
	d := xraySelectedTCPDefinitionFixture(t)
	compiled, err := d.validate()
	if err != nil {
		t.Fatal(err)
	}
	record := ExecutionResource{ID: "xr-" + strings.Repeat("a", 32), Kind: "xray-selected-tcp", State: "prepared", Phase: "planned", Generation: compiled.Generation, EffectsDigest: d.EffectsSHA256, XraySelectedTCP: &d}
	execution := Execution{PlanID: d.PlanID, Digest: d.PlanDigest, State: "prepared", Resources: []ExecutionResource{record}}
	if err := validateExecutionResources(execution, false); err != nil {
		t.Fatal("valid original Xray record refused", err)
	}
	record.SyntheticBaseline = &ExecutionSyntheticBaselineDefinition{}
	if err := validateXraySelectedTCPExecutionResource(record, false); err == nil {
		t.Fatal("mixed synthetic/Xray record passed native resource validation")
	}
	execution.Resources[0] = record
	if err := validateExecutionResources(execution, false); err == nil {
		t.Fatal("mixed synthetic/Xray record passed journal validation")
	}
}
