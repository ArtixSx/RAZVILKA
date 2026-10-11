package dataplane

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/dnscontrol"
)

func TestSyntheticBaselineIssuerRefusesUnoriginalMappingBeforeReservation(t *testing.T) {
	m, adapter, plan, scope, parent := syntheticExecutionModel(t)
	ctx := scope.contextWith(parent)
	binding, err := m.BindSyntheticDNSExecution(ctx, adapter, plan)
	if err != nil {
		t.Fatal(err)
	}
	for _, source := range []*dnscontrol.SyntheticDNSMapping{nil, {}} {
		resource, err := binding.issueBaseline(ctx, source, new(BackendInventory), new(DomainPolicyTCPCapture))
		if resource != nil || !(errors.Is(err, dnscontrol.ErrSyntheticDNSMapping) || errors.Is(err, ErrSyntheticBaselineTransition)) {
			t.Fatal("unoriginal source entered COMMON issuer", resource, err)
		}
	}
	if len(scope.execution.Resources) != 0 {
		t.Fatal("refused source registered intent")
	}
	if err := scope.close(); err != nil {
		t.Fatal(err)
	}
	if resource, err := binding.issueBaseline(context.WithoutCancel(ctx), nil, nil, nil); resource != nil || err == nil {
		t.Fatal("detached cancellation revived a closed issuer")
	}
}

func TestSyntheticBaselineResourceCannotUseReceiptMetadataAsOriginalSource(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	// Valid detached intent from the existing journal model still has no live
	// registration, mapping, held tools, control, original reader or capture.
	definition := executionSyntheticResourceFixture(t).Resources[0].SyntheticBaseline
	effects, err := syntheticBaselineDefinitionEffects(definition)
	if err != nil {
		t.Fatal(err)
	}
	r := &syntheticBaselineExecutionResource{definition: definition, effects: effects, mapping: new(dnscontrol.SyntheticDNSMapping), backend: new(BackendInventory), capture: new(DomainPolicyTCPCapture)}
	r.self = r
	for _, candidate := range []*syntheticBaselineExecutionResource{nil, {}, r} {
		if err := candidate.prepareBaseline(ctx); !errors.Is(err, ErrSyntheticBaselineTransition) {
			t.Fatal(err)
		}
		if prepared, err := candidate.prepareCapture(ctx); prepared != nil || !errors.Is(err, ErrSyntheticBaselineTransition) {
			t.Fatal(prepared, err)
		}
	}
	if r.prepared {
		t.Fatal("metadata-only preparation became baseline ACK")
	}
}

func TestSyntheticBaselineStartRejectsCopiedAndUnissuedOwnerBeforeBegin(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	r := &syntheticBaselineExecutionResource{}
	r.self = r
	copy := &syntheticBaselineExecutionResource{self: r}
	for _, runner := range []*syntheticBaselineEffectRunner{nil, {}, {resource: r}, {resource: copy}} {
		starts := 0
		err := runner.WithStart(ctx, "iptables", []string{"-t", "nat", "-N", "RZSB_0123456789abcdef0123"}, "", func() error { starts++; return nil })
		if !errors.Is(err, ErrSyntheticBaselineTransition) || starts != 0 {
			t.Fatal("unissued owner entered tool Start", err, starts)
		}
		if _, err := runner.Run(ctx, "iptables", "-F"); !errors.Is(err, ErrSyntheticBaselineTransition) {
			t.Fatal(err)
		}
	}
}

func TestSyntheticBaselineUnknownAttemptNeverRetriesOrPreparesCapture(t *testing.T) {
	unknown := errors.Join(ErrPolicyAdditionUnknown, context.DeadlineExceeded)
	r := &syntheticBaselineExecutionResource{failed: unknown}
	r.self = r
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	for range 2 {
		if err := r.prepareBaseline(ctx); !errors.Is(err, ErrPolicyAdditionUnknown) || !errors.Is(err, context.DeadlineExceeded) {
			t.Fatal(err)
		}
		if prepared, err := r.prepareCapture(ctx); prepared != nil || !errors.Is(err, ErrPolicyAdditionUnknown) {
			t.Fatal(prepared, err)
		}
	}
	if r.prepared {
		t.Fatal("unknown attempt advanced preparation")
	}
}
