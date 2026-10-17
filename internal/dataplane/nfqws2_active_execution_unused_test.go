package dataplane

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/netidentity"
	"github.com/ArtixSx/razvilka/internal/operationgate"
)

// Actual original registrar, protected roots, Gate/control and BOTH journal
// writers. Only NI/kernel/process absence is explicitly modeled; no Native
// Start, actual App source or active-owner permission is claimed.
func nfqwsUnlaunchedFixture(t *testing.T) (*nfqws2ActiveExecution, context.Context) {
	t.Helper()
	e, ctx, _ := nfqwsUnlaunchedAcquireFixture(t, "issued")
	return e, ctx
}

func nfqwsUnlaunchedAcquireFixture(t *testing.T, outcome string) (*nfqws2ActiveExecution, context.Context, *executionResourceScope) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	t.Cleanup(cancel)
	var admission operationgate.Gate
	ctx, release, err := admission.ExclusiveContext(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(release)
	controlRoot := filepath.Join(t.TempDir(), "control")
	if _, err := operationgate.InitializeSelfUpdateControl(ctx, controlRoot); err != nil {
		t.Fatal(err)
	}
	control, err := admission.ReviewControlEpoch(ctx, controlRoot)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = control.Close() })
	cleanup, err := control.ReviewExclusiveCleanup(ctx)
	if err != nil {
		t.Fatal(err)
	}
	ctx = WithReviewGuard(ctx, control.Current)
	m := New(t.TempDir())
	a := NewNFQWS2Adapter()
	if err := m.Register(a); err != nil {
		t.Fatal(err)
	}
	command, spec, _ := nfqws2ActiveCommandFixture(t)
	command.StateRoot, command.ControlRoot = a.StateRoot, controlRoot
	command.Owner, err = a.owner()
	if err != nil {
		t.Fatal(err)
	}
	epoch := control.Reference()
	command.InstallationID, command.Sequence = epoch.InstallationID, epoch.Sequence
	spec.CommandSHA256 = nfqws2ActiveCommandDigest(command)
	plan, _, _ := nfqwsScopedFixture(t)
	plan.PlanID, plan.NetworkProfileID, plan.Adapters = "dp-0123456789abcdef", "wan-0123456789ab", []string{"nfqws2"}
	plan.Routes[0].NetworkPolicyRole = "override"
	m.FreshProfile = func(context.Context) (string, error) { return plan.NetworkProfileID, nil }
	identity, current := networkPolicyIdentityFixture()
	*current, identity.value = *spec.NetworkIdentity, *spec.NetworkIdentity
	lan, _, _ := lanReceiptBindingFixture(t)
	gate, err := newNetworkPolicyIdentityAdapter(NetworkPolicyAssemblyOptions{Binding: lan, InventoryCheck: func(context.Context, netidentity.Identity, *LANPolicyRuntimePlan) error { return nil }}, identity)
	if err != nil || m.Register(gate) != nil {
		t.Fatal(err)
	}
	if err := m.beginOperation(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(m.endOperation)
	execution := Execution{PlanID: plan.PlanID, Digest: plan.Digest, State: "applying", StartedAt: time.Now().UTC().Format(time.RFC3339Nano)}
	root := filepath.Join(m.StateRoot, "transactions", plan.PlanID)
	if err := m.prepareExecutionRoot(root); err != nil {
		t.Fatal(err)
	}
	scope, err := m.newExecutionResourceScope(ctx, plan, a.ID(), &execution, root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = scope.close() })
	if err := scope.persist(); err != nil {
		t.Fatal(err)
	}
	ctx = context.WithValue(scope.contextWith(ctx), nfqwsExecutionReadbackKey{}, nfqwsExecutionReadback(func(context.Context, *NFQWSScopedPlan, string, nfqwsExecutionReadbackMode) error { return nil }))
	request := spec.Clone()
	switch outcome {
	case "known":
		request.NetworkIdentity = nil // The original issuer refuses before any mutation.
	case "journal-error":
		if err := os.WriteFile(filepath.Join(root, "execution-resources"), []byte("unknown"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	r, acquireErr := AcquireNFQWSExecutionResource(ctx, request)
	if outcome == "issued" && (r == nil || acquireErr != nil) || outcome == "known" && (r != nil || !errors.Is(acquireErr, ErrNetworkPolicyIdentity)) || outcome == "journal-error" && (r != nil || !errors.Is(acquireErr, ErrExecutionJournal)) {
		t.Fatal("unexpected original Acquire outcome", outcome, acquireErr)
	}
	if acquireErr == nil {
		acquireErr = ErrNFQWSScopedOwner // A later known pre-producer preparation refusal.
	}
	material := &NFQWSActiveMaterial{manager: m, managerRoot: m.StateRoot, adapter: a, control: control, command: command, intent: nfqws2ActiveIntentFromCommand(command)}
	material.self = material
	e := &nfqws2ActiveExecution{material: material, plan: plan, spec: spec, resource: r, cleanup: cleanup, started: true, preparationErr: acquireErr}
	e.self = e
	// Explicit already-issued seal model; this fixture has no App/source owner.
	selection := &NFQWSScopedSelection{spec: spec}
	selection.self = selection
	e.selection = selection
	seal := &nfqws2ActiveActivationSeal{execution: e, scope: scope, selection: selection, command: command.clone(), spec: spec.Clone(), consumed: true}
	seal.self, e.activationSeal = seal, seal
	a.activeExecution = e
	return e, ctx, scope
}

func TestNFQWSUnlaunchedAcquireRefusalBeforeResource(t *testing.T) {
	for _, outcome := range []string{"known", "journal-error"} {
		t.Run(outcome, func(t *testing.T) {
			e, ctx, scope := nfqwsUnlaunchedAcquireFixture(t, outcome)
			if e.resource != nil || len(scope.execution.Resources) != 0 || len(scope.nfqws) != 0 {
				t.Fatal("Acquire issued or recorded a resource before refusal")
			}
			paths := []string{filepath.Join(scope.root, "execution.json"), filepath.Join(scope.managerRoot, "latest-execution.json")}
			before := make([][]byte, len(paths))
			for i, path := range paths {
				var err error
				before[i], err = os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
			}
			reads := 0
			err := e.settleUnlaunched(ctx, func(context.Context) error { reads++; return nil })
			if outcome == "known" {
				if err != nil || reads != 2 || e.material.adapter.activeExecution != nil || !e.retired {
					t.Fatal("known pre-mutation refusal did not release after both absence observations", reads, err)
				}
			} else if err == nil || reads != 0 || e.material.adapter.activeExecution != e || e.retired {
				t.Fatal("uncertain original issuer failure released the association", reads, err)
			}
			for i, path := range paths {
				after, err := os.ReadFile(path)
				if err != nil || string(before[i]) != string(after) {
					t.Fatal("no-resource refusal rewrote an original execution record", err)
				}
			}
		})
	}
}

func TestNFQWSUnlaunchedKnownRefusalClosesOriginalReservationInBothRecords(t *testing.T) {
	e, ctx := nfqwsUnlaunchedFixture(t)
	reads := 0
	if err := e.settleUnlaunched(ctx, func(context.Context) error { reads++; return nil }); err != nil {
		t.Fatal(err)
	}
	if reads != 2 {
		t.Fatal("absence did not bracket both real writes", reads)
	}
	for _, path := range []string{filepath.Join(e.resource.scope.root, "execution.json"), filepath.Join(e.material.managerRoot, "latest-execution.json")} {
		var recorded *Execution
		present, err := readOptionalJournal(path, &recorded)
		if err != nil || !present || recorded == nil || !reflect.DeepEqual(*recorded, *e.resource.scope.execution) || recorded.Resources[0].State != "removed" || recorded.Resources[0].Phase != "removed" {
			t.Fatal("unused outcome missing from original records", err)
		}
	}
	if e.material.adapter.activeExecution != nil || e.material.adapter.activeProcess != nil || !e.retired || e.launchInvoked || e.prepared != nil {
		t.Fatal("known unused close retained association or launched a process")
	}
}

func TestNFQWSProducerCompletionClosesOnlyOriginalUnusedReservation(t *testing.T) {
	for _, kind := range []string{"original", "missing", "different-execution", "different-command", "physical-unknown"} {
		t.Run(kind, func(t *testing.T) {
			e, ctx := nfqwsUnlaunchedFixture(t)
			e.launchInvoked = true
			e.noLaunch = &nfqws2ActiveNoLaunch{execution: e, command: nfqws2ActiveCommandDigest(e.material.command)}
			switch kind {
			case "missing":
				e.noLaunch = nil
			case "different-execution":
				e.noLaunch.execution = &nfqws2ActiveExecution{}
			case "different-command":
				e.noLaunch.command = "different"
			}
			reads := 0
			err := e.settleUnlaunched(ctx, func(context.Context) error {
				reads++
				if kind == "physical-unknown" {
					return ErrNFQWSScopedOwner
				}
				return nil
			})
			if kind == "original" {
				if err != nil || !e.retired || !e.launchInvoked || reads != 2 || e.resource.scope.execution.Resources[0].Phase != "removed" {
					t.Fatalf("original completion: %v reads=%d", err, reads)
				}
			} else if err == nil || e.retired || e.material.adapter.activeExecution != e {
				t.Fatalf("unknown completion released owner: %v", err)
			}
		})
	}
}

func TestNFQWSUnlaunchedUnknownNeverReleasesOrRepairsReservation(t *testing.T) {
	for _, name := range []string{"journal-error", "native-invoked", "sticky-writer", "receipt", "lock", "divergent-record", "unknown-json-field", "duplicate-json-field", "unknown-absence"} {
		t.Run(name, func(t *testing.T) {
			e, ctx := nfqwsUnlaunchedFixture(t)
			observe := func(context.Context) error { return nil }
			switch name {
			case "journal-error":
				e.preparationErr = ErrExecutionJournal
			case "native-invoked":
				e.launchInvoked = true
			case "sticky-writer":
				e.resource.scope.failure = ErrExecutionJournal
			case "receipt":
				if err := os.WriteFile(filepath.Join(e.resource.Root(), policyAdditionFile), []byte("unknown"), 0600); err != nil {
					t.Fatal(err)
				}
			case "lock":
				if err := os.WriteFile(filepath.Join(e.resource.Root(), policyAdditionLock), nil, 0600); err != nil {
					t.Fatal(err)
				}
			case "divergent-record":
				if err := os.WriteFile(filepath.Join(e.material.managerRoot, "latest-execution.json"), []byte("{}"), 0600); err != nil {
					t.Fatal(err)
				}
			case "unknown-json-field", "duplicate-json-field":
				path := filepath.Join(e.material.managerRoot, "latest-execution.json")
				original, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				prefix := `{"unknown":true,`
				if name == "duplicate-json-field" {
					prefix = `{"plan_id":"` + e.plan.PlanID + `",`
				}
				if err := os.WriteFile(path, append([]byte(prefix), original[1:]...), 0600); err != nil {
					t.Fatal(err)
				}
				var decoded *Execution
				if present, err := readOptionalJournal(path, &decoded); err != nil || !present || decoded == nil || !reflect.DeepEqual(*decoded, *e.resource.scope.execution) {
					t.Fatal("fixture did not demonstrate permissive-decoder equivalence", err)
				}
			case "unknown-absence":
				observe = func(context.Context) error { return ErrNFQWSScopedOwner }
			}
			before, err := os.ReadFile(filepath.Join(e.material.managerRoot, "latest-execution.json"))
			if err != nil {
				t.Fatal(err)
			}
			if err := e.settleUnlaunched(ctx, observe); err == nil {
				t.Fatal("unknown outcome became unused permission")
			}
			after, err := os.ReadFile(filepath.Join(e.material.managerRoot, "latest-execution.json"))
			if err != nil || string(before) != string(after) || e.material.adapter.activeExecution != e || e.resource.scope.execution.Resources[0].State != "prepared" {
				t.Fatal("unknown fence was repaired/cleared", err)
			}
		})
	}
}

func TestNFQWSUnlaunchedClosingUnknownKeepsAssociationAfterJournalClose(t *testing.T) {
	e, ctx := nfqwsUnlaunchedFixture(t)
	reads := 0
	err := e.settleUnlaunched(ctx, func(context.Context) error {
		reads++
		if reads == 2 {
			return errors.New("closing native observation unknown")
		}
		return nil
	})
	if err == nil || e.material.adapter.activeExecution != e || e.retired {
		t.Fatal("closing unknown released original association")
	}
}
