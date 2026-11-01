package dataplane

import (
	"context"
	"errors"
	"testing"
)

func TestXrayDomainNativePhaseCancellationPreservesRealCallbackErrors(t *testing.T) {
	m, a, plan, scope, ctx := syntheticExecutionModel(t)
	b, err := m.BindSyntheticDNSExecution(scope.contextWith(ctx), a, plan)
	if err != nil {
		t.Fatal(err)
	}
	defer b.phase.Close()
	request, cancel := context.WithCancel(ctx)
	defer cancel()
	witness := errors.New("actual callback cleanup failure")
	err = b.phase.withDomainNativeActivity(request, func(held context.Context) error {
		cancel()
		<-held.Done()
		return witness
	})
	if !errors.Is(err, witness) || !errors.Is(err, context.Canceled) {
		t.Fatal("exception or cancellation lost", err)
	}
	if errors.Is(err, ErrDomainTransportRuntime) {
		t.Fatal("canceled forward predicate fabricated unavailable exception", err)
	}
}

func TestXrayDomainNativePhaseLiveClosingSourceStillRequired(t *testing.T) {
	m, a, plan, scope, ctx := syntheticExecutionModel(t)
	b, err := m.BindSyntheticDNSExecution(scope.contextWith(ctx), a, plan)
	if err != nil {
		t.Fatal(err)
	}
	defer b.phase.Close()
	called := false
	err = b.phase.withDomainNativeActivity(ctx, func(context.Context) error {
		called = true
		return m.Register(&fakeAdapter{id: "domain-native-phase-changed"})
	})
	if !called || err == nil {
		t.Fatal("live closing source bookend omitted", called, err)
	}
}
