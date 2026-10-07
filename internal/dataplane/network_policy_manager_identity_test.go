package dataplane

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/ArtixSx/razvilka/internal/netidentity"
)

// Explicit identity/kernel models only; no fake provider is exposed by the
// production factory and these tests do not observe or mutate networking.
func networkPolicyIdentityFixture() (*networkPolicyIdentity, *netidentity.Identity) {
	current := netidentity.Identity{Version: 1, Kind: netidentity.ProcNetInode, BootID: "01234567-89ab-cdef-0123-456789abcdef", Inode: 12345}
	frozen := current
	return &networkPolicyIdentity{value: frozen, withCurrent: func(ctx context.Context, use func(context.Context, netidentity.Identity) error) error {
		before := current
		if err := use(ctx, before); err != nil {
			return err
		}
		if current != before || ctx.Err() != nil {
			return errors.Join(netidentity.ErrUnknown, ctx.Err())
		}
		return nil
	}}, &current
}

func networkPolicyTypedGateFixture(t *testing.T) (*Manager, Plan, *NetworkPolicyAdapter, *lanPolicyReceiptModel, *netidentity.Identity) {
	t.Helper()
	old, plan, gate, consumer, model := networkPolicyGateManagerFixture(t)
	identity, current := networkPolicyIdentityFixture()
	options := NetworkPolicyAssemblyOptions{Binding: gate.Binding, InventoryCheck: func(_ context.Context, got netidentity.Identity, lan *LANPolicyRuntimePlan) error {
		if got != identity.value || lan != nil && !reflect.DeepEqual(lan, model.plan) {
			return ErrLANPolicyRuntime
		}
		if lan == nil {
			for _, count := range model.present {
				if count != 0 {
					return ErrRuntimeInactivity
				}
			}
		}
		return nil
	}}
	typed, err := newNetworkPolicyIdentityAdapter(options, identity)
	if err != nil {
		t.Fatal(err)
	}
	manager := New(old.StateRoot)
	manager.FreshProfile = old.FreshProfile
	consumer.gate = typed
	for _, adapter := range []Adapter{typed, consumer} {
		if err := manager.Register(adapter); err != nil {
			t.Fatal(err)
		}
	}
	return manager, plan, typed, model, current
}

func TestNetworkPolicyManagerIdentityFactoryMissingOwnersRefusesReadOnly(t *testing.T) {
	if _, err := NewNetworkPolicyAdapter(context.Background(), NetworkPolicyAssemblyOptions{}); !errors.Is(err, ErrNetworkPolicyIdentity) {
		t.Fatal("missing provider/owners granted runtime", err)
	}
	b, model, _ := lanReceiptBindingFixture(t)
	for _, mutate := range []func(*NetworkPolicyAssemblyOptions){
		func(o *NetworkPolicyAssemblyOptions) { o.InventoryCheck = nil },
		func(o *NetworkPolicyAssemblyOptions) { o.Binding = nil },
		func(o *NetworkPolicyAssemblyOptions) { b := *o.Binding; b.ApplyGuard = nil; o.Binding = &b },
		func(o *NetworkPolicyAssemblyOptions) { b := *o.Binding; b.CleanupGuard = nil; o.Binding = &b },
		func(o *NetworkPolicyAssemblyOptions) { b := *o.Binding; b.RetireCheck = nil; o.Binding = &b },
	} {
		options := NetworkPolicyAssemblyOptions{Provider: &netidentity.Provider{}, Binding: b, InventoryCheck: func(context.Context, netidentity.Identity, *LANPolicyRuntimePlan) error { return nil }}
		mutate(&options)
		if _, err := NewNetworkPolicyAdapter(context.Background(), options); !errors.Is(err, ErrNetworkPolicyIdentity) {
			t.Fatal("missing owner granted runtime", err)
		}
	}
	if len(model.calls) != 0 {
		t.Fatal("constructor performed kernel effects")
	}
}

func TestNetworkPolicyManagerIdentityActualGateRetainsTypedOwnerUntilStop(t *testing.T) {
	manager, plan, gate, model, current := networkPolicyTypedGateFixture(t)
	execution, err := manager.Apply(context.Background(), plan, nil)
	if err != nil || execution.State != "committed" {
		t.Fatal("typed shared gate apply", execution, err)
	}
	owner, err := gate.readOwner()
	if err != nil || owner.Schema != 2 || owner.NetworkIdentity == nil || *owner.NetworkIdentity != *current || !owner.Promoted {
		t.Fatal("full typed owner not retained", owner, err)
	}
	if len(model.calls) == 0 || gate.Reconcile(context.Background(), plan) != nil {
		t.Fatal("actual shared gate/receipt not observed")
	}
	if _, err := manager.Deactivate(context.Background()); err != nil {
		t.Fatal("typed gate Stop failed", err)
	}
	if err := manager.VerifyRuntimeInactive(context.Background()); err != nil {
		t.Fatal("typed gate did not settle exact absence", err)
	}
}

func TestNetworkPolicyManagerIdentityLegacyOrForeignOwnerCannotDelete(t *testing.T) {
	for _, fault := range []string{"legacy", "other-inode", "other-boot"} {
		t.Run(fault, func(t *testing.T) {
			manager, plan, gate, model, _ := networkPolicyTypedGateFixture(t)
			if _, err := manager.Apply(context.Background(), plan, nil); err != nil {
				t.Fatal(err)
			}
			owner, err := gate.readOwner()
			if err != nil {
				t.Fatal(err)
			}
			switch fault {
			case "legacy":
				owner.Schema, owner.NetworkIdentity = 1, nil
			case "other-inode":
				owner.NetworkIdentity.Inode++
			case "other-boot":
				owner.NetworkIdentity.BootID = "fedcba98-7654-3210-fedc-ba9876543210"
			}
			if err := writeNetworkPolicyGate(gate.ownerPath(), owner); err != nil {
				t.Fatal(err)
			}
			before, _ := os.ReadFile(gate.ownerPath())
			calls := len(model.calls)
			if gate.Deactivate(context.Background()) == nil || gate.VerifyRuntimeInactive(context.Background()) == nil {
				t.Fatal("old/foreign owner granted cleanup or absence")
			}
			after, _ := os.ReadFile(gate.ownerPath())
			if !bytes.Equal(before, after) || len(model.calls) != calls {
				t.Fatal("refusal changed receipt/ownership/kernel effects")
			}
		})
	}
}

type networkPolicyIdentityTestRunner struct {
	calls int
	after func()
}

func (r *networkPolicyIdentityTestRunner) Run(context.Context, string, ...string) ([]byte, error) {
	r.calls++
	if r.after != nil {
		r.after()
	}
	return []byte("observed"), nil
}

func TestNetworkPolicyManagerIdentityCLIBracketRefusesOpeningAndClosingDrift(t *testing.T) {
	for _, closing := range []bool{false, true} {
		identity, current := networkPolicyIdentityFixture()
		base := &networkPolicyIdentityTestRunner{}
		if closing {
			base.after = func() { current.Inode++ }
		} else {
			current.Inode++
		}
		runner := networkPolicyIdentityRunner{identity: identity, runner: base}
		if _, err := runner.Run(context.Background(), "read-only-model"); err == nil || base.calls != map[bool]int{false: 0, true: 1}[closing] {
			t.Fatal("identity drift admitted/stated successful CLI", closing, base.calls, err)
		}
	}
}

func TestNetworkPolicyManagerIdentityNFQJournalWireAndDefensiveCopy(t *testing.T) {
	identity, _ := networkPolicyIdentityFixture()
	execution := executionNFQWSResourceFixture(t, "removed")
	execution.Resources[0].State = "removed"
	execution.State, execution.FinishedAt = "committed", execution.StartedAt
	bindNetworkPolicyTypedExecutionFixture(t, &execution, identity.value)
	manager := New(privateScopedXrayFixtureDir(t))
	root := filepath.Join(manager.StateRoot, "transactions", execution.PlanID)
	if err := os.MkdirAll(root, 0700); err != nil {
		t.Fatal(err)
	}
	if err := manager.writeExecution(root, execution); err != nil {
		t.Fatal(err)
	}
	if err := manager.CheckExecutionRecovery(context.Background()); err != nil {
		t.Fatal("canonical typed identity did not round-trip both journals", err)
	}
	copy := cloneExecutionResources(execution.Resources)
	copy[0].NFQWS.NetworkIdentity.Inode++
	if execution.Resources[0].NFQWS.NetworkIdentity.Inode != identity.value.Inode || validateExecutionResources(Execution{PlanID: execution.PlanID, Digest: execution.Digest, Resources: copy}, false) == nil {
		t.Fatal("typed identity clone aliased or foreign inode passed")
	}
	for _, identityJSON := range []string{`"net:[12345]"`, `{"version":1,"kind":"reviewed-single-init-net","boot_id":"01234567-89ab-cdef-0123-456789abcdef","inode":0,"platform_review_sha256":""}`} {
		var definition ExecutionNFQWSDefinition
		if json.Unmarshal([]byte(`{"network_identity":`+identityJSON+`}`), &definition) == nil {
			t.Fatal("legacy string/unknown singleton decoded as typed identity")
		}
	}
}

func TestNetworkPolicyManagerIdentityIssuerRetainsProofAndRefusesLateDrift(t *testing.T) {
	for _, fault := range []string{"missing-record-binding", "changed-live-inode", "changed-during-review"} {
		t.Run(fault, func(t *testing.T) {
			f := executionNFQWSManagerFixture(t)
			identity, current := networkPolicyIdentityFixture()
			f.spec.NetworkIdentity = &identity.value
			binding, _, _ := lanReceiptBindingFixture(t)
			gate, err := newNetworkPolicyIdentityAdapter(NetworkPolicyAssemblyOptions{Binding: binding, InventoryCheck: func(context.Context, netidentity.Identity, *LANPolicyRuntimePlan) error { return nil }}, identity)
			if err != nil || f.m.Register(gate) != nil {
				t.Fatal("model typed gate registration", err)
			}
			called := false
			err = f.m.WithExecutionResources(f.ctx, f.p, "nfqws2", func(ctx context.Context) error {
				f.bind(t, ctx)
				recorded := f.latest(t).Resources[0].NFQWS.NetworkIdentity
				if recorded == nil || *recorded != identity.value || f.r.Current(ctx, f.r.Binding()) != nil {
					t.Fatal("issuer failed to retain original typed proof")
				}
				switch fault {
				case "missing-record-binding":
					f.r.scope.execution.Resources[0].NFQWS.NetworkIdentity = nil
				case "changed-live-inode":
					current.Inode++
				case "changed-during-review":
					f.r.scope.guard = func(context.Context) error { current.Inode++; return nil }
				}
				if f.r.Current(ctx, f.r.Binding()) == nil {
					t.Fatal("lost/changed typed proof renewed borrowed authority")
				}
				called = true
				return nil
			})
			if !called || !errors.Is(err, ErrExecutionJournal) || len(f.model.calls) != 0 {
				t.Fatal("unresolved owner lost fence or performed effects", err, f.model.calls)
			}
		})
	}
}
