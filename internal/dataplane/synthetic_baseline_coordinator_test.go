package dataplane

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/dnscontrol"
	"github.com/ArtixSx/razvilka/internal/operationgate"
)

func TestSyntheticBaselineCoordinatorToolsOnlyCannotRegisterOriginalSource(t *testing.T) {
	m, adapter, plan, scope, parent := syntheticExecutionModel(t)
	ctx := scope.contextWith(parent)
	binding, err := m.BindSyntheticDNSExecution(ctx, adapter, plan)
	if err != nil {
		t.Fatal(err)
	}
	if coordinator, err := binding.bindBaselineCoordinator(ctx, new(SyntheticDNSCommandTools), new(BackendInventory), new(DomainPolicyTCPCapture)); coordinator != nil || err == nil {
		t.Fatal("tools/capture metadata created original coordinator")
	}
	if len(scope.execution.Resources) != 0 {
		t.Fatal("unopened source registered effects")
	}
}

func TestSyntheticBaselineSharedHooksRefuseMissingOrCopiedSourceBeforeJournal(t *testing.T) {
	m, adapter, plan, scope, parent := syntheticExecutionModel(t)
	ctx := scope.contextWith(parent)
	binding, err := m.BindSyntheticDNSExecution(ctx, adapter, plan)
	if err != nil {
		t.Fatal(err)
	}
	source := &syntheticBaselineCoordinator{binding: binding, tools: new(SyntheticDNSCommandTools), backend: new(BackendInventory), capture: new(DomainPolicyTCPCapture)}
	source.self = source
	copy := &syntheticBaselineCoordinator{self: source, binding: binding, tools: source.tools, backend: source.backend, capture: source.capture}
	for _, candidate := range []*syntheticBaselineCoordinator{nil, {}, source, copy} {
		if err := scope.registerSyntheticBaselineCoordinator(ctx, candidate); !errors.Is(err, ErrSyntheticBaselineTransition) {
			t.Fatal(err)
		}
	}
	if tools, err := scope.syntheticBaselineCommandTools(ctx, binding); tools != nil || !errors.Is(err, ErrSyntheticBaselineTransition) {
		t.Fatal(tools, err)
	}
	if resource, err := scope.lookupSyntheticBaseline(ctx, binding, new(dnscontrol.SyntheticDNSMapping), source.backend, source.capture); resource != nil || !errors.Is(err, ErrSyntheticBaselineTransition) {
		t.Fatal(resource, err)
	}
	r := &syntheticBaselineExecutionResource{binding: binding, mapping: new(dnscontrol.SyntheticDNSMapping), definition: executionSyntheticResourceFixture(t).Resources[0].SyntheticBaseline}
	r.self = r
	if err := scope.reserveSyntheticBaseline(ctx, r); !errors.Is(err, ErrSyntheticBaselineTransition) {
		t.Fatal(err)
	}
	if scope.syntheticBaselineSource != nil || len(scope.syntheticBaselines) != 0 || len(scope.execution.Resources) != 0 || scope.resourceCount() != 0 || r.root != "" || r.anchor != nil {
		t.Fatal("unoriginal source created journal/receipt owner")
	}
	if err := scope.close(); err != nil {
		t.Fatal(err)
	}
	if err := scope.registerSyntheticBaselineCoordinator(context.WithoutCancel(ctx), source); !errors.Is(err, ErrSyntheticBaselineTransition) {
		t.Fatal("closed scope granted source", err)
	}
}

func TestSyntheticBaselineCoordinatorCopiedAggregateAndMissingSourceRefuse(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	c := &syntheticBaselineCoordinator{binding: new(SyntheticDNSExecutionBinding), tools: new(SyntheticDNSCommandTools), backend: new(BackendInventory), capture: new(DomainPolicyTCPCapture), control: new(operationgate.ControlEpochReview)}
	c.self = c
	copy := &syntheticBaselineCoordinator{self: c, binding: c.binding, tools: c.tools, backend: c.backend, capture: c.capture, control: c.control}
	for _, source := range []*syntheticBaselineCoordinator{nil, {}, c, copy} {
		for _, request := range []context.Context{nil, context.Background(), ctx} {
			if err := source.Current(request); !errors.Is(err, ErrSyntheticBaselineTransition) {
				t.Fatal(err)
			}
		}
	}
}
