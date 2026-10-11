package dataplane

import (
	"os"
	"testing"

	"github.com/ArtixSx/razvilka/internal/dnscontrol"
)

// The real finite binding model cannot register a source or journal intent
// using detached tool/capture/metadata values. No native positive grant here.
func TestNetworkPolicyManagerSyntheticBaselineDetachedSourceCannotReserve(t *testing.T) {
	m, adapter, plan, scope, parent := syntheticExecutionModel(t)
	ctx := scope.contextWith(parent)
	b, err := m.BindSyntheticDNSExecution(ctx, adapter, plan)
	if err != nil {
		t.Fatal(err)
	}
	for _, source := range []*syntheticBaselineCoordinator{nil, {}, {binding: b, tools: new(SyntheticDNSCommandTools), backend: new(BackendInventory), capture: new(DomainPolicyTCPCapture)}} {
		if err := scope.registerSyntheticBaselineCoordinator(ctx, source); err == nil {
			t.Fatal("detached source registered")
		}
	}
	if _, err := scope.syntheticBaselineCommandTools(ctx, b); err == nil {
		t.Fatal("missing original source supplied tools")
	}
	if got, err := scope.lookupSyntheticBaseline(ctx, b, new(dnscontrol.SyntheticDNSMapping), new(BackendInventory), new(DomainPolicyTCPCapture)); err == nil || got != nil {
		t.Fatal("detached mapping adopted an original resource")
	}
	r := &syntheticBaselineExecutionResource{binding: b, definition: executionSyntheticResourceFixture(t).Resources[0].SyntheticBaseline}
	r.self = r
	if err := scope.reserveSyntheticBaseline(ctx, r); err == nil {
		t.Fatal("metadata reserved execution intent")
	}
	if scope.syntheticBaselineSource != nil || len(scope.syntheticBaselines) != 0 || len(scope.execution.Resources) != 0 || r.root != "" {
		t.Fatal("refused metadata altered source or journal")
	}
	if entries, err := os.ReadDir(scope.root); err != nil || len(entries) != 0 {
		t.Fatal("refusal created a resource directory", err)
	}
	if err := scope.close(); err != nil {
		t.Fatal(err)
	}
	if err := scope.currentSyntheticBaselineStart(ctx, r); err == nil {
		t.Fatal("closed scope allowed actual Start")
	}
}
