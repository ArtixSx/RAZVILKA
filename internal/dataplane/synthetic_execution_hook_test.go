package dataplane

import (
	"context"
	"testing"
)

func TestSyntheticExecutionHookUsesSameFiniteScopeAndPreservesOriginalContext(t *testing.T) {
	m, adapter, plan, scope, parent := syntheticExecutionModel(t) // Explicit physical/source model, no effects.
	type marker struct{}
	ctx := context.WithValue(parent, marker{}, "original")
	deadline, finite := ctx.Deadline()
	held := scope.contextWith(ctx)
	actual, bounded := held.Deadline()
	if !finite || !bounded || actual != deadline || held.Value(marker{}) != "original" || held.Value(syntheticExecutionRegistrarKey{}) != scope || held.Value(nfqws2ActiveActivationRegistrarKey{}) != scope || held.Value(nfqwsExecutionRegistrarKey{}) == nil || held.Value(nodeTransitRegistrarKey{}) == nil {
		t.Fatal("scope integration replaced original context or other issuer")
	}
	binding, err := m.BindSyntheticDNSExecution(held, adapter, plan)
	if err != nil {
		t.Fatal("actual finite scope hook not wired", err)
	}
	if _, err := m.BindSyntheticDNSExecution(ctx, adapter, plan); err == nil {
		t.Fatal("ordinary context reconstructed original issuer")
	}
	if err := scope.close(); err != nil {
		t.Fatal(err)
	}
	if err := binding.Current(held); err == nil {
		t.Fatal("closed finite scope revived")
	}
	if err := validateDomainTransportForExecution(plan); err == nil {
		t.Fatal("finite review hook granted runtime execution readiness")
	}
}
