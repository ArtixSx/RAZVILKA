package dataplane

import (
	"context"
	"testing"

	"github.com/ArtixSx/razvilka/internal/netidentity"
)

func TestManagedListBoundaryRunsFullOwnerOutsideProviderLeaf(t *testing.T) {
	_, plan, gate, _, model := networkPolicyGateManagerFixture(t)
	identity, _ := networkPolicyIdentityFixture()
	identity.mode = LANPolicyManagedListMode
	inside := false
	original := identity.withCurrent
	identity.withCurrent = func(ctx context.Context, use func(context.Context, netidentity.Identity) error) error {
		if inside {
			t.Fatal("Provider boundary reentered")
		}
		inside = true
		defer func() { inside = false }()
		return original(ctx, use)
	}
	physical, inventory := 0, 0
	gate.Binding.Runtime.ScopeCheck = func(context.Context, *LANPolicyRuntimePlan) error {
		if inside {
			t.Fatal("full owner ran under Provider")
		}
		physical++
		return nil
	}
	typed, err := newNetworkPolicyIdentityAdapter(NetworkPolicyAssemblyOptions{Mode: LANPolicyManagedListMode, Binding: gate.Binding, InventoryCheck: func(context.Context, netidentity.Identity, *LANPolicyRuntimePlan) error {
		if inside {
			t.Fatal("full inventory ran under outer Provider")
		}
		inventory++
		return nil
	}}, identity)
	if err != nil {
		t.Fatal(err)
	}
	if err := typed.Binding.Runtime.ScopeCheck(context.Background(), plan.LAN); err != nil {
		t.Fatal(err)
	}
	if physical != 1 || inventory != 1 || inside || model == nil {
		t.Fatal("actual boundary skipped owner/inventory/bookend")
	}
}
