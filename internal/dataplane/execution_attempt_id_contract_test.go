package dataplane

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ArtixSx/razvilka/internal/netidentity"
)

// The actual Manager, registered Xray dispatcher, original material and closed
// BindExecution run. Identity/physical/kernel facts use existing private models.
// The real BackendInventory collector stays UNKNOWN without a native provider:
// reaching that refusal proves entry into Snapshot, never native success.
func TestExecutionAttemptIDXrayManagerSnapshotBoundary(t *testing.T) {
	for _, test := range []struct {
		name                 string
		oldFormat, stockRows bool
	}{{"previous-digest-plus-nonce", true, false}, {"nonce-contract", false, false}, {"previous-id-cold-stock-rollback", true, true}} {
		t.Run(test.name, func(t *testing.T) {
			x := newXrayOperationFixture(t, func(spec *XraySelectedTCPRedirectSpec) {
				*spec = xraySelectedTCPFixtureOneClient(t, *spec, "mac")
				var err error
				spec.LAN, err = CompileXraySelectedTCPLANPolicyRuntime(spec.Generation, spec.LAN.Ingress)
				if err != nil {
					t.Fatal(err)
				}
			})
			x.originalScope(t)
			p := cloneExecutionResourcePlan(x.scope.plan)
			proof := x.material.material.proof
			if err := x.scope.close(); err != nil {
				t.Fatal(err)
			}
			if err := x.material.Close(); err != nil {
				t.Fatal(err)
			}
			p.Ready, p.Adapters = true, []string{NetworkPolicyAdapterID, "xray"}
			p.PlanID = "dp-0123456789abcdef"
			if test.oldFormat {
				p.PlanID = "dp-" + p.Digest[:16] + "-0123456789abcdef"
			}
			identity, _ := networkPolicyIdentityFixture()
			identity.mode = LANPolicyManagedListMode
			image := networkPolicyInventoryTestImage(identity.value, nil)
			if test.stockRows {
				image = nfqwsDirectStockReviewedVendorFixture()
				identity.value = image.Scope.Network
				identity.withCurrent = func(ctx context.Context, use func(context.Context, netidentity.Identity) error) error {
					return use(ctx, identity.value) // Explicit frozen identity model.
				}
				if stock, err := inspectXrayStockOutputQueues(image); err != nil || len(stock) != 2 {
					t.Fatal("stock image model is not an accepted comparison")
				}
			}
			binding, _, _ := lanReceiptBindingFixture(t)
			binding.CleanupGuard = func(ctx context.Context, _ *LANPolicyRuntimePlan, _ LANPolicyEffect) error { return ctx.Err() }
			var checks *NetworkPolicyChecks
			gate, err := newNetworkPolicyIdentityAdapter(NetworkPolicyAssemblyOptions{Mode: identity.mode, Binding: binding,
				InventoryCheck: func(ctx context.Context, got netidentity.Identity, lan *LANPolicyRuntimePlan) error {
					return checks.InventoryCheck(ctx, got, lan)
				}}, identity)
			if err != nil {
				t.Fatal(err)
			}
			if err := x.manager.Register(gate); err != nil {
				t.Fatal(err)
			}
			checks, err = x.manager.bindNetworkPolicyChecks(gate, func(_ context.Context, got netidentity.Identity) (BackendInventorySnapshot, error) {
				if got != image.Scope.Network {
					return BackendInventorySnapshot{}, ErrNetworkPolicyIdentity
				}
				return image, nil
			})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = checks.Close() })
			inventory := &BackendInventory{review: strings.Repeat("a", 64), reader: backendInventoryReader{
				IPTables: gate.Binding.Runtime.IPTables, IP6Tables: gate.Binding.Runtime.IP6Tables, Runner: gate.Binding.Runtime.Runner}}
			checks.inventory = inventory
			x.material, err = ReviewXrayOperationMaterial(x.ctx, x.manager, x.control, x.adapter, proof, x.spec)
			if err != nil {
				t.Fatal(err)
			}
			ctx := WithReviewGuard(x.ctx, func(ctx context.Context) error { return ctx.Err() })
			ctx, err = x.material.BindExecution(ctx, context.Background(), p, inventory, gate, checks,
				func(ctx context.Context, _ Plan) error { return ctx.Err() }, func(ctx context.Context, _ Plan) error { return ctx.Err() })
			if err != nil {
				t.Fatal(err)
			}
			x.manager.FreshProfile = func(context.Context) (string, error) { return p.NetworkProfileID, nil }
			result, err := x.manager.Apply(ctx, p, nil)
			if test.oldFormat {
				if !errors.Is(err, ErrNodeTransitUnavailable) || errors.Is(err, ErrBackendInventoryUnknown) {
					t.Fatal("previous ID did not refuse before Snapshot", err)
				}
			} else if !errors.Is(err, ErrBackendInventoryUnknown) || errors.Is(err, ErrNodeTransitUnavailable) {
				t.Fatal("contract ID did not reach original Snapshot inventory boundary", err)
			}
			if len(result.Steps) < 2 || result.Steps[0].Adapter != NetworkPolicyAdapterID || result.Steps[0].Phase != "snapshot" || result.Steps[0].State != "passed" ||
				result.Steps[1].Adapter != "xray" || result.Steps[1].Phase != "snapshot" || result.Steps[1].State != "failed" ||
				len(result.Resources) != 0 || x.material.execution.resource != nil || x.model.starts != 0 || x.model.stops != 0 || result.RollbackVerified {
				t.Fatal("snapshot boundary created effects or claimed joined rollback")
			}
			if test.stockRows {
				if !errors.Is(err, ErrLANPolicyRuntime) || LANPolicyPreflightFailureStage(err) != "inventory-row-unallowed" ||
					len(result.Steps) != 4 || result.Steps[2].Adapter != NetworkPolicyAdapterID || result.Steps[2].Phase != "rollback" ||
					result.Steps[2].Detail != ErrLANPolicyRuntime.Error() || result.Steps[3].Phase != "verify-rollback" ||
					result.Steps[3].Detail != ErrLANPolicyRuntime.Error() || result.State != "rollback-failed" {
					t.Fatal("cold no-resource stock rollback did not retain its strict inventory fence")
				}
			}
		})
	}
}

// NFQ's compiler retains an opaque review name rather than checking its format.
// Its actual Manager resource issuer enforces the closed contract; both full
// names/digests must survive the compiler comparison without normalization.
func TestExecutionAttemptIDNFQCompilerAndManagerScope(t *testing.T) {
	f := executionNFQWSManagerFixture(t)
	old := cloneExecutionResourcePlan(f.p)
	old.PlanID = "dp-" + old.Digest[:16] + "-0123456789abcdef"
	compiledOld, err := CompileNFQWSScopedPlan(old, f.spec)
	if err != nil || compiledOld.Resources().PlanID != old.PlanID || compiledOld.Resources().PlanDigest != old.Digest {
		t.Fatal("NFQ comparison compiler changed opaque review identity", err)
	}
	compiled, err := CompileNFQWSScopedPlan(f.p, f.spec)
	if err != nil || compiled.Resources().PlanID != f.p.PlanID || compiled.Resources().PlanDigest != f.p.Digest {
		t.Fatal("NFQ original compilation refused contract name", err)
	}
	for _, p := range []Plan{old, f.p} {
		execution := &Execution{PlanID: p.PlanID, Digest: p.Digest}
		root := filepath.Join(f.m.StateRoot, "transactions", p.PlanID)
		if err := f.m.prepareExecutionRoot(root); err != nil {
			t.Fatal(err)
		}
		scope, err := f.m.newExecutionResourceScope(f.ctx, p, "nfqws2", execution, root)
		if p.PlanID == old.PlanID {
			if scope != nil || !errors.Is(err, ErrNodeTransitUnavailable) {
				t.Fatal("old NFQ name reached resource issuer", err)
			}
			continue
		}
		if err != nil || scope.adapterOwner != f.m.Adapters["nfqws2"] || scope.execution != execution || len(execution.Resources) != 0 {
			t.Fatal("original NFQ scope lost its owner", err)
		}
		if err := scope.close(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestExecutionAttemptIDWGOriginalOwnerAndClose(t *testing.T) {
	adapter, owner, ctx, _, _, _ := wgNetworkCommandOwnerFixture(t)
	original := owner.scope
	old := cloneExecutionResourcePlan(original.plan)
	old.PlanID = "dp-" + old.Digest[:16] + "-0123456789abcdef"
	execution := &Execution{PlanID: old.PlanID, Digest: old.Digest}
	root := filepath.Join(original.manager.StateRoot, "transactions", old.PlanID)
	if scope, err := original.manager.newExecutionResourceScope(ctx, old, adapter.ID(), execution, root); scope != nil || !errors.Is(err, ErrNodeTransitUnavailable) {
		t.Fatal("old WG name reached original command owner", err)
	}
	if original.adapterOwner != adapter || original.wgOwner != owner || owner.check(ctx, false) != nil || len(original.execution.Resources) != 0 || owner.mutationAttempted.Load() {
		t.Fatal("contract WG name changed owner or attempted a command")
	}
	if _, err := owner.context(ctx); err != nil {
		t.Fatal("original WG owner refused its actual scope", err)
	}
	if err := owner.material.Close(); err != nil {
		t.Fatal(err)
	}
	if err := owner.check(ctx, false); err == nil {
		t.Fatal("closed WG material kept forward authority")
	}
}
