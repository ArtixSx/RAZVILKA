package dataplane

import (
	"context"
	"testing"
	"time"
)

// Actual original registrar and BOTH existing writers; only native absence is
// modeled. A removed definition is a comparison, never a terminal issuer.
func TestNFQWSRemovedResourceComparisonUsesOriginalTerminalDefinition(t *testing.T) {
	e, ctx := nfqwsUnlaunchedFixture(t)
	r := e.resource
	if nfqwsRemovedResourceDefinition(r) {
		t.Fatal("planned original resource appeared terminal")
	}
	if err := e.settleUnlaunched(ctx, func(context.Context) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if !nfqwsRemovedResourceDefinition(r) {
		t.Fatal("actual original removed record was not comparable")
	}
	copy := *r
	if nfqwsRemovedResourceDefinition(&copy) {
		t.Fatal("copied resource adopted original scope")
	}
	for _, cut := range []string{"phase", "generation", "effects", "mode", "identity", "duplicate", "scope-map"} {
		t.Run(cut, func(t *testing.T) {
			e, c := nfqwsUnlaunchedFixture(t)
			if err := e.settleUnlaunched(c, func(context.Context) error { return nil }); err != nil {
				t.Fatal(err)
			}
			r, s := e.resource, e.resource.scope
			record := &s.execution.Resources[0]
			switch cut {
			case "phase":
				record.Phase = "closed"
			case "generation":
				record.Generation = "foreign"
			case "effects":
				record.EffectsDigest = "foreign"
			case "mode":
				record.NFQWS.Mode = "foreign"
			case "identity":
				record.NFQWS.NetworkIdentity = nil
			case "duplicate":
				s.execution.Resources = append(s.execution.Resources, *record)
			case "scope-map":
				delete(s.nfqws, r.binding.ResourceID)
			}
			if nfqwsRemovedResourceDefinition(r) {
				t.Fatal("changed terminal metadata accepted", cut)
			}
		})
	}
}

func TestNFQWSRetiredInventoryContextIsFiniteOriginalAndRevocable(t *testing.T) {
	h, model, ctx, err := nfqws2RetiredHandleFixture(t, false)
	if err != nil {
		t.Fatal(err)
	}
	settled, err := model.owner.result()
	if err != nil {
		t.Fatal(err)
	}
	e := &nfqws2ActiveExecution{}
	e.self = e
	// Explicit private carrier model around an actual original terminal handle;
	// this has no production material/collector/COMMON owner and cannot admit
	// CheckRetiredManagedNFQWSAbsence below.
	model.owner.admission.execution = e
	checks := &NetworkPolicyChecks{}
	d, _ := ctx.Deadline()
	o := &nfqwsRetiredInventoryOperation{checks: checks, execution: e, handle: h, observation: settled.observation(), deadline: d}
	o.self = o
	o.open.Store(true)
	c := context.WithValue(ctx, nfqwsRetiredInventoryKey{}, o)
	if err := checkNFQWSRetiredInventoryContext(c, checks, e); err != nil {
		t.Fatal("original private terminal carrier refused", err)
	}
	for _, cut := range []string{"copied", "closed", "wrong-execution", "wrong-checks", "unbounded", "cancelled", "longer-deadline", "foreign-observation"} {
		t.Run(cut, func(t *testing.T) {
			carrier := &nfqwsRetiredInventoryOperation{self: o, checks: checks, execution: e, handle: h, observation: settled.observation(), deadline: d}
			carrier.open.Store(true)
			bad := c
			switch cut {
			case "copied":
				bad = context.WithValue(ctx, nfqwsRetiredInventoryKey{}, carrier)
			case "closed":
				o.open.Store(false)
				defer o.open.Store(true)
			case "wrong-execution":
				if checkNFQWSRetiredInventoryContext(c, checks, &nfqws2ActiveExecution{}) == nil {
					t.Fatal("foreign execution adopted terminal carrier")
				}
				return
			case "wrong-checks":
				if checkNFQWSRetiredInventoryContext(c, &NetworkPolicyChecks{}, e) == nil {
					t.Fatal("foreign checks adopted terminal carrier")
				}
				return
			case "unbounded":
				bad = context.WithValue(context.Background(), nfqwsRetiredInventoryKey{}, o)
			case "cancelled":
				var cancel context.CancelFunc
				bad, cancel = context.WithCancel(c)
				cancel()
			case "longer-deadline":
				var cancel context.CancelFunc
				bad, cancel = context.WithDeadline(context.Background(), time.Now().Add(time.Hour))
				defer cancel()
				bad = context.WithValue(bad, nfqwsRetiredInventoryKey{}, o)
			case "foreign-observation":
				o.observation.Receipt.CommandSHA256 = "foreign"
				defer func() { o.observation = settled.observation() }()
			}
			if checkNFQWSRetiredInventoryContext(bad, checks, e) == nil {
				t.Fatal("foreign/expired/revoked terminal carrier accepted", cut)
			}
		})
	}
	unused, unusedCtx := nfqwsUnlaunchedFixture(t)
	checks.manager = unused.material.manager
	if err := checks.manager.CheckRetiredManagedNFQWSAbsence(unusedCtx, unused.cleanup, h, settled.observation(), checks); err == nil {
		t.Fatal("genuine terminal plus another original resource minted ownership")
	}
}
