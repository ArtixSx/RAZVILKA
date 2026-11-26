package dataplane

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
)

// A phase model of the native573 boundary: actual original Gate/control and
// Manager registrar, but no public source factory, native process or packets.
// LAN has entered Activate while NFQ has not issued its seal or resource.
func preResourcePendingScope(t *testing.T) (*preEffectLANFixture, *executionResourceScope, *nfqwsPendingScopeClaim) {
	t.Helper()
	f := newPreEffectLANFixture(t)
	m := f.e.material.manager
	f.e.plan.Adapters = []string{NetworkPolicyAdapterID, "nfqws2"}
	f.e.comparisonSelection.plan = cloneExecutionResourcePlan(f.e.plan)
	f.e.lanActivationAttempted = true
	execution := &Execution{PlanID: f.e.plan.PlanID, Digest: f.e.plan.Digest}
	s, claim, err := m.newNFQWSExecutionResourceScope(f.ctx, f.e.plan, "nfqws2", execution, filepath.Dir(f.root))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.close() })
	return f, s, claim
}

func TestNFQWSPreResourcePendingRefusesCopiedAndMissingClaims(t *testing.T) {
	for _, cut := range []string{"missing", "copied-claim", "copied-scope", "foreign-execution", "foreign-resource"} {
		t.Run(cut, func(t *testing.T) {
			f, s, claim := preResourcePendingScope(t)
			m := f.e.material.manager
			ctx, suppliedScope := f.ctx, s
			switch cut {
			case "missing":
				claim = nil
			case "copied-claim":
				copy := *claim
				claim = &copy
			case "copied-scope":
				suppliedScope = &executionResourceScope{manager: m, adapterOwner: s.adapterOwner, plan: s.plan, open: true}
			case "foreign-execution":
				ctx = context.WithValue(ctx, nfqws2ActiveExecutionKey{}, &nfqws2ActiveExecution{})
			case "foreign-resource":
				f.e.resource = &NFQWSExecutionResource{scope: &executionResourceScope{}}
			}
			calls := 0
			if err := m.retainPendingNFQWS(ctx, suppliedScope, func(context.Context) error { calls++; return nil }, claim); err == nil {
				t.Fatal("invalid tuple accepted")
			}
			if calls != 0 {
				t.Fatal("retention executed cleanup")
			}
			if cut == "missing" || cut == "copied-claim" {
				if m.HasPendingManagedNFQWS() || s.pending {
					t.Fatal("unissued claim minted owner")
				}
				return
			}
			if !m.HasPendingManagedNFQWS() || m.pendingNFQ.scope != s || m.pendingNFQ.execution != f.e || m.pendingNFQ.blocked == nil || !s.open {
				t.Fatal("failed retain lost or replaced actual original owner")
			}
			if err := m.JoinPendingManagedNFQWS(f.ctx); err == nil || calls != 0 || !m.HasPendingManagedNFQWS() {
				t.Fatal("blocked original acquired cleanup authority", err, calls)
			}
		})
	}
}

func TestNFQWSPreResourcePendingRetainsBothConflictingOriginals(t *testing.T) {
	f, s, claim := preResourcePendingScope(t)
	m := f.e.material.manager
	calls := 0
	join := func(context.Context) error { calls++; return nil }
	if err := m.retainPendingNFQWS(f.ctx, s, join, claim); err != nil {
		t.Fatal(err)
	}
	first := m.pendingNFQ
	if err := m.retainPendingNFQWS(f.ctx, s, join, claim); err == nil {
		t.Fatal("conflict accepted")
	}
	if m.pendingNFQ != first || first.conflict == nil || first.conflict.scope != s || !s.open {
		t.Fatal("conflict dropped original")
	}
	if err := m.JoinPendingManagedNFQWS(f.ctx); err == nil || calls != 0 {
		t.Fatal("ambiguous owner joined", err, calls)
	}
}

func TestNFQWSPreResourcePendingLANActivatedUnknownKeepsStrictOriginalCleanup(t *testing.T) {
	f := newPreEffectLANFixture(t)
	m := f.e.material.manager
	f.e.plan.Adapters = []string{NetworkPolicyAdapterID, "nfqws2"}
	f.e.comparisonSelection.plan = cloneExecutionResourcePlan(f.e.plan)
	f.snapshot(t, false)
	if err := f.e.gate.Activate(f.ctx, f.e.plan, f.root); err != nil {
		t.Fatal("actual modeled LAN preparation", err)
	}
	if !f.e.lanActivationAttempted || f.e.neverActivatedLAN() {
		t.Fatal("activated LAN became no-effect")
	}
	execution := &Execution{PlanID: f.e.plan.PlanID, Digest: f.e.plan.Digest}
	s, claim, err := m.newNFQWSExecutionResourceScope(f.ctx, f.e.plan, "nfqws2", execution, filepath.Dir(f.root))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.close() })
	f.physical = errors.New("modeled original packet source unavailable")
	calls := 0
	join := func(ctx context.Context) error {
		calls++
		if ctx.Value(nfqws2ActiveExecutionKey{}) != f.e {
			t.Fatal("replacement execution")
		}
		if err := f.e.gate.Rollback(ctx, f.e.plan, f.root); err != nil {
			return err
		}
		ok, err := f.e.gate.VerifyRollback(ctx, f.e.plan, f.root)
		if err != nil || !ok {
			return errors.Join(ErrLANPolicyRuntime, err)
		}
		return nil
	}
	if err := join(f.ctx); err == nil {
		t.Fatal("revoked physical source permitted cleanup")
	}
	if err := m.retainPendingNFQWS(f.ctx, s, join, claim); err != nil {
		t.Fatal(err)
	}
	if err := m.pendingNFQ.join(s.contextWith(f.ctx)); err == nil || calls != 2 || !m.HasPendingManagedNFQWS() || !s.open {
		t.Fatal("unknown original cleanup released", err, calls)
	}
	if owner, err := f.e.gate.readOwner(); err != nil || owner == nil {
		t.Fatal("unknown LAN intent forgotten", err)
	}
	// This fixture intentionally has no genuine independent source/provider.
	// Public Join must refuse it rather than use the Snapshot no-effect proof.
	if err := m.JoinPendingManagedNFQWS(f.ctx); err == nil || calls != 2 || !m.HasPendingManagedNFQWS() {
		t.Fatal("incomplete source bypassed strict preflight", err, calls)
	}
	// Exercise only the retained ORIGINAL compensation leaf after its modeled
	// physical observer recovers. This does not claim a native/public Join PASS.
	f.physical = nil
	if err := m.pendingNFQ.join(s.contextWith(f.ctx)); err != nil || calls != 3 {
		t.Fatal("original strict compensation retry", err, calls)
	}
	if owner, err := f.e.gate.readOwner(); err != nil || owner != nil {
		t.Fatal("verified original intent not retired", err)
	}
}

func TestNFQWSPreResourcePendingRetainsOriginalRegistrarWithoutResource(t *testing.T) {
	f, s, claim := preResourcePendingScope(t)
	m := f.e.material.manager
	calls := 0
	join := func(context.Context) error { calls++; return ErrNetworkPolicyAuthority }
	if f.e.resource != nil || f.e.activationSeal != nil || f.e.started {
		t.Fatal("model fabricated activation")
	}
	if err := m.retainPendingNFQWS(f.ctx, s, join, claim); err != nil {
		t.Fatal("original registrar before resource was lost", err)
	}
	if !m.HasPendingManagedNFQWS() || !s.pending || !s.open || m.pendingNFQ.scope != s || m.pendingNFQ.execution != f.e || calls != 0 {
		t.Fatal("pending original owner/closure not retained")
	}
}

func TestNFQWSPreResourcePendingIssuedResourceStillRequiresSameRegistrar(t *testing.T) {
	f, s, claim := preResourcePendingScope(t)
	m := f.e.material.manager
	f.e.resource = &NFQWSExecutionResource{scope: s}
	ctx, cancel := context.WithCancel(f.ctx)
	cancel() // A failed original request still must retain its cleanup owners.
	if err := m.retainPendingNFQWS(ctx, s, func(context.Context) error { return nil }, claim); err != nil {
		t.Fatal("cancelled request lost original issued resource", err)
	}
	if !m.HasPendingManagedNFQWS() || !s.open || !s.pending {
		t.Fatal("cancelled original not held")
	}
	if err := m.JoinPendingManagedNFQWS(ctx); err == nil || !m.HasPendingManagedNFQWS() {
		t.Fatal("cancelled Join released owner", err)
	}
}

func TestNFQWSPreResourceLegacyRegistrarDoesNotMintScopedClaim(t *testing.T) {
	f := newPreEffectLANFixture(t)
	f.e.plan.Adapters = []string{NetworkPolicyAdapterID, "nfqws2"}
	execution := &Execution{PlanID: f.e.plan.PlanID, Digest: f.e.plan.Digest}
	ctx := context.WithValue(f.ctx, nfqws2ActiveExecutionKey{}, nil)
	s, claim, err := f.e.material.manager.newNFQWSExecutionResourceScope(ctx, f.e.plan, "nfqws2", execution, filepath.Dir(f.root))
	if err != nil || s == nil || claim != nil {
		t.Fatal("legacy registrar changed", err)
	}
	if err := s.close(); err != nil {
		t.Fatal(err)
	}
}
