package dataplane

import (
	"context"
	"path/filepath"
	"testing"
)

// A phase model of the native573 boundary: actual original Gate/control and
// Manager registrar, but no public source factory, native process or packets.
// LAN has entered Activate while NFQ has not issued its seal or resource.
func preResourcePendingScope(t *testing.T) (*preEffectLANFixture, *executionResourceScope) {
	t.Helper()
	f := newPreEffectLANFixture(t)
	m := f.e.material.manager
	f.e.plan.Adapters = []string{NetworkPolicyAdapterID, "nfqws2"}
	f.e.comparisonSelection.plan = cloneExecutionResourcePlan(f.e.plan)
	f.e.lanActivationAttempted = true
	execution := &Execution{PlanID: f.e.plan.PlanID, Digest: f.e.plan.Digest}
	s, err := m.newExecutionResourceScope(f.ctx, f.e.plan, "nfqws2", execution, filepath.Dir(f.root))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.close() })
	return f, s
}

func TestNFQWSPreResourcePendingRetainsOriginalRegistrarWithoutResource(t *testing.T) {
	f, s := preResourcePendingScope(t)
	m := f.e.material.manager
	calls := 0
	join := func(context.Context) error { calls++; return ErrNetworkPolicyAuthority }
	if f.e.resource != nil || f.e.activationSeal != nil || f.e.started {
		t.Fatal("model fabricated activation")
	}
	if err := m.retainPendingNFQWS(f.ctx, s, join); err != nil {
		t.Fatal("original registrar before resource was lost", err)
	}
	if !m.HasPendingManagedNFQWS() || !s.pending || !s.open || m.pendingNFQ.scope != s || m.pendingNFQ.execution != f.e || calls != 0 {
		t.Fatal("pending original owner/closure not retained")
	}
}
