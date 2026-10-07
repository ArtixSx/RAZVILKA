package dataplane

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/ArtixSx/razvilka/internal/netidentity"
)

func bindNetworkPolicyTypedExecutionFixture(t *testing.T, e *Execution, identity netidentity.Identity) {
	t.Helper()
	d := e.Resources[0].NFQWS
	d.Spec = d.Spec.Clone()
	d.Spec.NetworkIdentity = &identity
	if identity.Kind == netidentity.ReviewedSingleInitNet {
		d.Spec.NetNamespace = ""
	}
	d.NetworkIdentity = cloneNFQWSScopedNetworkIdentity(&identity)
	p, err := CompileNFQWSScopedPlan(d.Plan, d.Spec)
	if err != nil {
		t.Fatal(err)
	}
	e.Resources[0].Generation, e.Resources[0].EffectsDigest = p.Resources().Generation, p.Digest()
}

func TestNetworkPolicyManagerNFQWSTypedSpecBothJournalCopies(t *testing.T) {
	for _, kind := range []netidentity.Kind{netidentity.ProcNetInode, netidentity.ReviewedSingleInitNet} {
		t.Run(string(kind), func(t *testing.T) {
			identity, _ := networkPolicyIdentityFixture()
			network := identity.value
			if kind == netidentity.ReviewedSingleInitNet {
				network.Kind, network.Inode, network.PlatformReviewSHA256 = kind, 0, backendNFTStockScopeSHA256
			}
			e := executionNFQWSResourceFixture(t, "removed")
			e.State, e.FinishedAt, e.Resources[0].State = "committed", e.StartedAt, "removed"
			bindNetworkPolicyTypedExecutionFixture(t, &e, network)
			m := New(privateScopedXrayFixtureDir(t))
			root := filepath.Join(m.StateRoot, "transactions", e.PlanID)
			if err := os.MkdirAll(root, 0700); err != nil {
				t.Fatal(err)
			}
			if err := m.writeExecution(root, e); err != nil {
				t.Fatal(err)
			}
			for _, path := range []string{filepath.Join(root, "execution.json"), filepath.Join(m.StateRoot, "latest-execution.json")} {
				data, err := os.ReadFile(path)
				var decoded Execution
				var compact bytes.Buffer
				if err != nil || json.Compact(&compact, data) != nil || !bytes.Equal(data, compact.Bytes()) || json.Unmarshal(data, &decoded) != nil || !reflect.DeepEqual(decoded, e) {
					t.Fatal("typed full Spec did not round-trip exact compact journal", err)
				}
			}
			if err := New(m.StateRoot).CheckExecutionRecovery(context.Background()); err != nil {
				t.Fatal("known removed typed intent failed both-journal inspection", err)
			}
			copy := cloneExecutionResources(e.Resources)
			if copy[0].NFQWS.Spec.NetworkIdentity == e.Resources[0].NFQWS.Spec.NetworkIdentity || copy[0].NFQWS.NetworkIdentity == e.Resources[0].NFQWS.NetworkIdentity {
				t.Fatal("typed identity pointers aliased")
			}
			copy[0].NFQWS.Spec.NetworkIdentity.BootID = "11234567-89ab-cdef-0123-456789abcdef"
			copy[0].NFQWS.Spec.Candidate.Traffic[0].First++
			if *e.Resources[0].NFQWS.Spec.NetworkIdentity != network || validateExecutionResources(e, true) != nil {
				t.Fatal("copy changed original compiler definition")
			}
			if validateExecutionResources(Execution{PlanID: e.PlanID, Digest: e.Digest, Resources: copy}, false) == nil {
				t.Fatal("altered copy retained full typed binding")
			}
		})
	}
}

func TestNetworkPolicyManagerNFQWSTypedDefinitionRejectsMissingMixedAndForeignFields(t *testing.T) {
	for _, kind := range []netidentity.Kind{netidentity.ProcNetInode, netidentity.ReviewedSingleInitNet} {
		for name, mutate := range map[string]func(*ExecutionNFQWSDefinition){
			"missing spec identity":       func(d *ExecutionNFQWSDefinition) { d.Spec.NetworkIdentity = nil },
			"missing definition identity": func(d *ExecutionNFQWSDefinition) { d.NetworkIdentity = nil },
			"version":                     func(d *ExecutionNFQWSDefinition) { d.Spec.NetworkIdentity.Version++ },
			"kind":                        func(d *ExecutionNFQWSDefinition) { d.Spec.NetworkIdentity.Kind = "unknown" },
			"boot": func(d *ExecutionNFQWSDefinition) {
				d.Spec.NetworkIdentity.BootID = "11234567-89ab-cdef-0123-456789abcdef"
			},
			"inode": func(d *ExecutionNFQWSDefinition) { d.Spec.NetworkIdentity.Inode++ },
			"profile": func(d *ExecutionNFQWSDefinition) {
				d.Spec.NetworkIdentity.PlatformReviewSHA256 = strings.Repeat("a", 64)
			},
			"old boot":      func(d *ExecutionNFQWSDefinition) { d.Spec.BootID = "11234567-89ab-cdef-0123-456789abcdef" },
			"old namespace": func(d *ExecutionNFQWSDefinition) { d.Spec.NetNamespace = "net:[012345]" },
		} {
			t.Run(string(kind)+"/"+name, func(t *testing.T) {
				identity, _ := networkPolicyIdentityFixture()
				network := identity.value
				if kind == netidentity.ReviewedSingleInitNet {
					network.Kind, network.Inode, network.PlatformReviewSHA256 = kind, 0, backendNFTStockScopeSHA256
				}
				e := executionNFQWSResourceFixture(t, "planned")
				bindNetworkPolicyTypedExecutionFixture(t, &e, network)
				mutate(e.Resources[0].NFQWS)
				if err := validateExecutionResources(e, false); !errors.Is(err, ErrExecutionJournal) {
					t.Fatal("mixed/foreign identity acquired retained compiler binding", err)
				}
			})
		}
	}
}

func TestNetworkPolicyManagerNFQWSTypedSpecCannotBorrowUntypedScopeOrLegacyString(t *testing.T) {
	for _, typedManager := range []bool{false, true} {
		t.Run(map[bool]string{false: "typed-spec-untyped-manager", true: "legacy-spec-typed-manager"}[typedManager], func(t *testing.T) {
			f := executionNFQWSManagerFixture(t)
			identity, _ := networkPolicyIdentityFixture()
			if typedManager {
				binding, _, _ := lanReceiptBindingFixture(t)
				gate, err := newNetworkPolicyIdentityAdapter(NetworkPolicyAssemblyOptions{Binding: binding, InventoryCheck: func(context.Context, netidentity.Identity, *LANPolicyRuntimePlan) error { return nil }}, identity)
				if err != nil || f.m.Register(gate) != nil {
					t.Fatal(err)
				}
			} else {
				f.spec.NetworkIdentity = &identity.value
			}
			called := false
			err := f.m.WithExecutionResources(f.ctx, f.p, "nfqws2", func(ctx context.Context) error {
				ctx = context.WithValue(ctx, nfqwsExecutionReadbackKey{}, nfqwsExecutionReadback(func(context.Context, *NFQWSScopedPlan, string, nfqwsExecutionReadbackMode) error {
					t.Fatal("owner readback invoked for unbound compiler scope")
					return nil
				}))
				if _, err := AcquireNFQWSExecutionResource(ctx, f.spec); !errors.Is(err, ErrNetworkPolicyIdentity) {
					t.Fatal("missing typed scope acquired resource", err)
				}
				if len(f.latest(t).Resources) != 0 {
					t.Fatal("scope mismatch persisted a reservation")
				}
				called = true
				return nil
			})
			if !called || err != nil || len(f.model.calls) != 0 {
				t.Fatal("pure refusal changed kernel effects or fenced empty operation", err)
			}
		})
	}
}
