package dataplane

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/evidence"
)

// Identity comparison only, not an issued runtime: no Provider/control/source
// or native permission is modeled as successful. Real phases must still refuse.
func nfqwsRetryIdentityFixture(t *testing.T) (*nfqws2ActiveExecution, context.Context, string) {
	t.Helper()
	p, spec, _ := nfqwsScopedFixture(t)
	p.PlanID, p.Protocol = "dp-0123456789abcdef", []string{"plan", "snapshot", "stage", "validate", "activate", "health", "commit-or-rollback"}
	p.RouteEvidence = []RouteEvidence{{ServiceID: p.Routes[0].ServiceID, Route: "nfqws2", Required: evidence.Route, Observed: evidence.Route}}
	a := NewNFQWS2Adapter()
	a.Runner = &nfqwsFakeRunner{}
	m := &NFQWSActiveMaterial{adapter: a, managerRoot: t.TempDir()}
	m.self = m
	e := &nfqws2ActiveExecution{material: m, plan: cloneExecutionResourcePlan(p), spec: spec.Clone(), retired: true}
	e.self = e
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	t.Cleanup(cancel)
	return e, context.WithValue(ctx, nfqws2ActiveExecutionKey{}, e), filepath.Join(m.managerRoot, "transactions", p.PlanID, a.ID())
}

func nfqwsRetryResult(p Plan) Plan {
	p = cloneExecutionResourcePlan(p)
	// Exactly the Manager rollback closure's result publications. It retains
	// the same Plan for retries after the first LAN rollback was inconclusive.
	p.Ready, p.State, p.Note, p.ObservedEvidence = false, "rollback-failed", "original cleanup remains pending", evidence.None
	for i := range p.RouteEvidence {
		p.RouteEvidence[i].Observed = evidence.None
	}
	return p
}

func TestNFQWSOriginalRetryReadinessResultKeepsSameParticipant(t *testing.T) {
	e, ctx, root := nfqwsRetryIdentityFixture(t)
	a := e.material.adapter
	for _, p := range []Plan{e.plan, nfqwsRetryResult(e.plan), nfqwsRetryResult(nfqwsRetryResult(e.plan))} {
		if got, present, err := nfqws2ActiveExecutionFor(ctx, a, p, root); err != nil || !present || got != e {
			t.Fatal("Manager rollback result lost the original participant before fresh cleanup proof", err)
		}
	}
}

func TestNFQWSOriginalRetryStillRejectsChangedIntentAndCopiedOwners(t *testing.T) {
	e, ctx, root := nfqwsRetryIdentityFixture(t)
	for name, mutate := range map[string]func(*Plan){
		"route":    func(p *Plan) { p.Routes[0].Resolved = "sing-box" },
		"CIDR":     func(p *Plan) { p.Routes[0].CIDRs[0] = "9.9.9.9/32" },
		"digest":   func(p *Plan) { p.Digest = strings.Repeat("a", 64) },
		"protocol": func(p *Plan) { p.Protocol[0] = "changed-protocol" },
		"source":   func(p *Plan) { p.Routes[0].Sources[0] = "192.168.2.0/24" },
		"ingress":  func(p *Plan) { p.Routes[0].Ingress[0] = "other0" },
		"scope":    func(p *Plan) { p.LAN.Ingress[0].Sources[0] = "192.168.2.0/24" },
		"negative": func(p *Plan) { p.LAN.Ingress[0].ExcludedMACs[0] = "02:00:00:00:00:99" },
		"revision": func(p *Plan) { p.Revision++ },
		"proof":    func(p *Plan) { p.RouteEvidence[0].Required = evidence.None },
	} {
		t.Run(name, func(t *testing.T) {
			p := nfqwsRetryResult(e.plan)
			mutate(&p)
			if got, present, err := nfqws2ActiveExecutionFor(ctx, e.material.adapter, p, root); got != nil || !present || !errors.Is(err, ErrNFQWSScopedOwner) {
				t.Fatal("readiness normalization accepted changed intent", err)
			}
		})
	}
	p := nfqwsRetryResult(e.plan)
	copy := &nfqws2ActiveExecution{self: e, material: e.material, plan: e.plan, spec: e.spec, retired: true}
	for _, supplied := range []any{copy, p, e.spec, (*nfqws2ActiveExecution)(nil)} {
		if got, present, err := nfqws2ActiveExecutionFor(context.WithValue(ctx, nfqws2ActiveExecutionKey{}, supplied), e.material.adapter, p, root); got != nil || !present || !errors.Is(err, ErrNFQWSScopedOwner) {
			t.Fatal("copied handle/DTO became original participant", err)
		}
	}
}

func TestNFQWSOriginalRetryIdentityDoesNotIssueOwnership(t *testing.T) {
	e, ctx, root := nfqwsRetryIdentityFixture(t)
	p := nfqwsRetryResult(e.plan)
	data, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	var decoded Plan
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if got, present, err := nfqws2ActiveExecutionFor(context.WithValue(ctx, nfqws2ActiveExecutionKey{}, decoded), e.material.adapter, decoded, root); got != nil || !present || !errors.Is(err, ErrNFQWSScopedOwner) {
		t.Fatal("result JSON issued actual ownership", err)
	}
	// Even the original private identity below has no issued runtime owners.
	// Readiness neutrality must not bypass those independent phase guards.
	if err := e.material.adapter.Rollback(ctx, p, root); err == nil {
		t.Fatal("identity-only fixture gained rollback authority")
	}
	if ok, err := e.material.adapter.VerifyRollback(ctx, p, root); ok || err == nil {
		t.Fatal("identity-only fixture certified absence")
	}
	if len(e.material.adapter.Runner.(*nfqwsFakeRunner).calls) != 0 {
		t.Fatal("identity-only retry reached a command")
	}
}
