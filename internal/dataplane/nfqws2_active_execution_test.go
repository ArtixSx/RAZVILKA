package dataplane

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/evidence"
)

func TestNFQWSActiveExecutionMissingOwnersAndGuardsCannotBind(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	guard := func(context.Context, *NFQWSActiveHandle, NFQWSActiveObservation) error { return nil } // Explicit refusal model only.
	original := &NFQWSActiveMaterial{}
	original.self = original
	for _, material := range []*NFQWSActiveMaterial{nil, {}, original} {
		for _, guards := range [][2]NFQWSActiveGuard{{nil, nil}, {guard, nil}, {nil, guard}, {guard, guard}} {
			got, err := material.BindExecution(ctx, ctx, Plan{}, &NFQWSScopedSelection{}, &BackendInventory{}, &NetworkPolicyAdapter{}, guards[0], guards[1])
			if got != nil || err == nil || original.executionBound {
				t.Fatal("missing original owners/guards bound execution")
			}
		}
	}
}

func TestNFQWSActiveExecutionInvalidContextNeverFallsBackToPackage(t *testing.T) {
	root := t.TempDir()
	paths := []string{filepath.Join(root, "nfqws.conf"), filepath.Join(root, "user.list"), filepath.Join(root, "ipset.list"), filepath.Join(root, "init")}
	for _, path := range paths {
		if err := os.WriteFile(path, []byte("original external package bytes\n"), 0700); err != nil {
			t.Fatal(err)
		}
	}
	runner := &nfqwsFakeRunner{}
	a := &NFQWS2Adapter{ConfigPath: paths[0], UserListPath: paths[1], IPSetListPath: paths[2], InitPath: paths[3], Runner: runner}
	p := Plan{PlanID: "dp-0123456789abcdef"}
	material := &NFQWSActiveMaterial{adapter: a, managerRoot: root}
	material.self = material
	original := &nfqws2ActiveExecution{material: material, plan: p}
	original.self = original // Only an identity model; it has no actual owners.
	var copied nfqws2ActiveExecution
	reflect.ValueOf(&copied).Elem().Set(reflect.ValueOf(original).Elem())
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	phaseRoot := filepath.Join(root, "transactions", p.PlanID, a.ID())
	if err := os.MkdirAll(phaseRoot, 0700); err != nil {
		t.Fatal(err)
	}
	for _, supplied := range []any{true, NFQWSScopedSpec{}, (*nfqws2ActiveExecution)(nil), &nfqws2ActiveExecution{}, &copied, original} {
		current := context.WithValue(ctx, nfqws2ActiveExecutionKey{}, supplied)
		for _, phase := range []func(context.Context, Plan, string) error{a.Snapshot, a.Stage, a.Validate, a.Activate, a.Health, a.Commit, a.Rollback} {
			if err := phase(current, p, phaseRoot); err == nil {
				t.Fatal("invalid participant accepted phase or fell through to package")
			}
		}
		if ok, err := a.VerifyRollback(current, p, phaseRoot); ok || err == nil {
			t.Fatal("invalid participant certified rollback")
		}
	}
	if len(runner.calls) != 0 || a.activeProcess != nil || a.activeExecution != nil {
		t.Fatal("invalid participant performed process/package effects")
	}
	entries, err := os.ReadDir(phaseRoot)
	if err != nil || len(entries) != 0 {
		t.Fatal("invalid participant created package snapshot/staging or resource metadata", err)
	}
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil || string(data) != "original external package bytes\n" {
			t.Fatal("invalid participant changed external package", err)
		}
	}
}

func TestNFQWSActiveExecutionPhaseIdentityIncludesOriginalAdapterPlanAndRoot(t *testing.T) {
	root := t.TempDir()
	a := NewNFQWS2Adapter()
	p := Plan{PlanID: "dp-0123456789abcdef", Revision: 7, Routes: []Route{{ServiceID: "service", Resolved: "nfqws2"}}}
	material := &NFQWSActiveMaterial{adapter: a, managerRoot: root}
	material.self = material
	e := &nfqws2ActiveExecution{material: material, plan: cloneExecutionResourcePlan(p)}
	e.self = e
	ctx := context.WithValue(context.Background(), nfqws2ActiveExecutionKey{}, e)
	phaseRoot := filepath.Join(root, "transactions", p.PlanID, a.ID())
	if got, present, err := nfqws2ActiveExecutionFor(ctx, a, p, phaseRoot); got != e || !present || err != nil {
		t.Fatal("original identity model failed", err)
	}
	foreign := NewNFQWS2Adapter()
	changed := cloneExecutionResourcePlan(p)
	changed.Routes[0].Sources = []string{"192.168.1.0/24"}
	for _, test := range []struct {
		adapter *NFQWS2Adapter
		plan    Plan
		root    string
	}{{foreign, p, phaseRoot}, {a, changed, phaseRoot}, {a, p, filepath.Join(root, "foreign")}} {
		if got, present, err := nfqws2ActiveExecutionFor(ctx, test.adapter, test.plan, test.root); got != nil || !present || err == nil {
			t.Fatal("foreign phase identity accepted")
		}
	}
	result := cloneExecutionResourcePlan(p)
	result.State, result.Note, result.ObservedEvidence = "rolled-back", "known compensation", evidence.None
	if !nfqws2ActiveSamePlan(p, result) {
		t.Fatal("Manager result fields changed intent identity")
	}
	result.Revision++
	if nfqws2ActiveSamePlan(p, result) {
		t.Fatal("different actual revision retained old intent identity")
	}
}

func TestNFQWSActiveExecutionAssociationClosesLegacyOperations(t *testing.T) {
	a := NewNFQWS2Adapter()
	a.Runner = &nfqwsFakeRunner{}
	a.activeExecution = &nfqws2ActiveExecution{} // Explicit invalid association model.
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	for _, phase := range []func(context.Context, Plan, string) error{a.Snapshot, a.Stage, a.Validate, a.Activate, a.Health, a.Commit, a.Rollback} {
		if err := phase(ctx, Plan{}, t.TempDir()); err == nil {
			t.Fatal("associated participant fell through to package")
		}
	}
	if a.Reconcile(ctx, Plan{}) == nil || a.Deactivate(ctx) == nil {
		t.Fatal("legacy operation bypassed associated participant")
	}
	if len(a.Runner.(*nfqwsFakeRunner).calls) != 0 {
		t.Fatal("legacy init ran with active participant")
	}
}

// These use the existing explicit private process protocol model. They prove
// the assembly consumes original owner pointers, never genuine native Start.
func TestNFQWSActiveExecutionProcessReadRequiresOriginalPreparedOwner(t *testing.T) {
	m := nfqws2ActiveOwnerFixture(t)
	a := NewNFQWS2Adapter()
	m.owner.adapter = a
	a.activeProcess = m.owner
	p, _, _ := nfqwsScopedFixture(t)
	compiled, err := CompileNFQWSScopedPlan(p, m.owner.admission.Spec)
	if err != nil {
		t.Fatal(err)
	}
	material := &NFQWSActiveMaterial{adapter: a, command: m.owner.command}
	material.self = material
	e := &nfqws2ActiveExecution{material: material, prepared: m.prepared, resource: &NFQWSExecutionResource{plan: compiled, binding: m.lease.Binding}}
	e.self = e
	if proof, err := e.process(m.request, compiled, false); err != nil || proof != m.lease.proof() {
		t.Fatal("original modeled process reader failed", err)
	}
	e.prepared = &NFQWSPreparedHandle{owner: m.owner}
	if _, err := e.process(m.request, compiled, false); err == nil {
		t.Fatal("copied prepared handle became process proof")
	}
	e.prepared = m.prepared
	if _, err := e.process(m.request, compiled, true); err == nil {
		t.Fatal("running metadata became inactive without sole Wait")
	}
	stopped, err := m.prepared.Stop(m.request)
	if err != nil {
		t.Fatal(err)
	}
	if proof, err := e.process(m.request, compiled, true); err != nil || proof != stopped {
		t.Fatal("original modeled sole Wait/ACK result failed", err)
	}
	foreign := NewNFQWS2Adapter()
	material.adapter = foreign
	if _, err := e.process(m.request, compiled, false); err == nil {
		t.Fatal("foreign adapter association became process proof")
	}
}
