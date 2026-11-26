package dataplane

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/ArtixSx/razvilka/internal/netidentity"
)

func TestLANPolicyPreflightPreservesOriginalInnerBoundaryDiagnostic(t *testing.T) {
	for _, stage := range []string{"boundary-physical", "boundary-inventory", "boundary-identity"} {
		t.Run(stage, func(t *testing.T) {
			b, model, _ := lanDirectReceiptFixture(t)
			physical, inventory := 0, 0
			b.Runtime.ScopeCheck = func(context.Context, *LANPolicyRuntimePlan) error {
				physical++
				if stage == "boundary-physical" {
					return ErrReviewChanged
				}
				return nil
			}
			identity, current := networkPolicyIdentityFixture()
			identity.mode = LANPolicyNFQWSDirectMode
			gate, err := newNetworkPolicyIdentityAdapter(NetworkPolicyAssemblyOptions{Mode: LANPolicyNFQWSDirectMode, Binding: b,
				InventoryCheck: func(context.Context, netidentity.Identity, *LANPolicyRuntimePlan) error {
					inventory++
					return ErrReviewChanged
				}}, identity)
			if err != nil {
				t.Fatal(err)
			}
			if stage == "boundary-identity" {
				current.Inode++
			}
			err = gate.Binding.Runtime.Preflight(context.Background(), model.plan)
			if err == nil || LANPolicyPreflightFailureStage(err) != stage {
				t.Fatal("outer scope label hid original refusing boundary", stage, err, LANPolicyPreflightFailureStage(err))
			}
			wantPhysical, wantInventory := 1, 0
			if stage == "boundary-inventory" {
				wantInventory = 1
			}
			if stage == "boundary-identity" {
				wantPhysical = 0
				if !errors.Is(err, ErrNetworkPolicyIdentity) {
					t.Fatal("identity cause lost", err)
				}
			} else if !errors.Is(err, ErrReviewChanged) || err.Error() != ErrReviewChanged.Error() {
				t.Fatal("original presentation/cause changed", err)
			}
			if physical != wantPhysical || inventory != wantInventory || len(model.calls) != 0 {
				t.Fatal("diagnostic changed refusal order or performed effects", physical, inventory, model.calls)
			}
		})
	}
	inner := lanPolicyPreflightAt("inventory-row-unallowed", ErrLANPolicyRuntime)
	if got := lanPolicyPreflightAt("scope-open", errors.Join(ErrReviewChanged, inner)); LANPolicyPreflightFailureStage(got) != "inventory-row-unallowed" || !errors.Is(got, ErrReviewChanged) || !errors.Is(got, ErrLANPolicyRuntime) {
		t.Fatal("joined inner coordinate or causes lost", got)
	}
}

func TestLANPolicyPreflightRuntimePrerequisiteDiagnostics(t *testing.T) {
	for _, stage := range []string{"runtime-plan", "runtime-tools", "runtime-scope-missing"} {
		t.Run(stage, func(t *testing.T) {
			r := runtimeWithReadRunner(&lanRuntimeReadRunner{ip: map[string]string{}, firewall: map[string]string{}})
			plan := lanRuntimeFixture(t)
			switch stage {
			case "runtime-plan":
				plan.Digest = strings.Repeat("f", 64)
			case "runtime-tools":
				r.Runner = nil
			case "runtime-scope-missing":
				r.ScopeCheck = nil
			}
			err := r.Preflight(context.Background(), plan)
			if !errors.Is(err, ErrLANPolicyRuntime) || err.Error() != ErrLANPolicyRuntime.Error() || LANPolicyPreflightFailureStage(err) != stage {
				t.Fatal("prerequisite refusal obscured", stage, err)
			}
		})
	}
}

func TestNetworkPolicyInventoryClosedDiagnosticsKeepPredicate(t *testing.T) {
	identity, _ := networkPolicyIdentityFixture()
	for _, stage := range []string{"inventory-mode", "inventory-coverage", "inventory-identity", "inventory-definition", "inventory-row-shape", "inventory-row-syntax", "inventory-row-key", "inventory-row-unallowed", "inventory-row-order", "inventory-consumer-required"} {
		t.Run(stage, func(t *testing.T) {
			lan := lanRuntimeFixture(t)
			image := networkPolicyInventoryTestImage(identity.value, networkPolicyInventoryLANRows(lan))
			mode := ""
			var consumers []networkPolicyProxyObservation
			cause := ErrLANPolicyRuntime
			switch stage {
			case "inventory-mode":
				mode = "unknown private mode"
			case "inventory-coverage":
				image.Coverage.RegisteredTablesComplete = false
				cause = ErrBackendInventoryUnknown
			case "inventory-identity":
				image.Scope.Network.Inode++
				cause = ErrBackendInventoryUnknown
			case "inventory-definition":
				lan.Digest = strings.Repeat("f", 64)
			case "inventory-row-shape":
				image.Rows[0].Family = 17
				cause = ErrBackendInventoryUnknown
			case "inventory-row-syntax":
				image.Rows[0].Tokens = []string{"-N", "private", "ambiguous"}
				cause = ErrBackendInventoryUnknown
			case "inventory-row-key":
				image.Rows = append(image.Rows, BackendInventoryRow{Family: 4, Table: "mangle", Tokens: strings.Fields("-A RZQ_private -m vendor --ndmmark private -j NFQUEUE --queue-num 64511")})
			case "inventory-row-unallowed":
				image.Rows = append(image.Rows, BackendInventoryRow{Family: 6, Table: "raw", Tokens: strings.Fields("-A PREROUTING -j NFQUEUE --queue-num 201")})
			case "inventory-row-order":
				image.Rows[1], image.Rows[2] = image.Rows[2], image.Rows[1]
			case "inventory-consumer-required":
				consumers = []networkPolicyProxyObservation{{rows: []BackendInventoryRow{{Family: 4, Table: "filter", Tokens: []string{"-N", "RZP_private"}}}}}
				cause = ErrNetworkPolicyConsumers
			}
			err := checkNetworkPolicyInventoryForMode(image, identity.value, lan, mode, consumers)
			if !errors.Is(err, cause) || LANPolicyPreflightFailureStage(lanPolicyPreflightAt("scope-open", err)) != stage {
				t.Fatal("closed diagnostic changed predicate or hid reason", stage, err, LANPolicyPreflightFailureStage(err))
			}
			if stage != "inventory-coverage" && err.Error() != cause.Error() {
				t.Fatal("diagnostic changed error presentation", err)
			}
		})
	}
}
