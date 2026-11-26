package dataplane

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/ArtixSx/razvilka/internal/netidentity"
)

type lanDirectRPDBModel struct{ reads int }

func (m *lanDirectRPDBModel) Run(ctx context.Context, tool string, args ...string) ([]byte, error) {
	if tool != "ip" || len(args) != 4 || args[1] != "-N" || args[2] != "rule" || args[3] != "show" {
		return nil, errors.New("direct mode tried a table or effect instead of complete inventory")
	}
	m.reads++
	return []byte("0: from all lookup 255\n100: from all fwmark 0x1/0xffffffff lookup 1000\n32766: from all lookup 254\n32767: from all lookup 253\n"), ctx.Err()
}

// Actual registered Manager/typed participant/anchored inventory bookends.
// Identity, physical facts and full kernel captures are explicit leaf models.
func TestLANDirectOriginalParticipantPreservesFirmwareMarksAndRequiresWholeInventory(t *testing.T) {
	old, _, _, consumer, _ := networkPolicyGateManagerFixture(t)
	b, model, root := lanDirectReceiptFixture(t)
	identity, _ := networkPolicyIdentityFixture()
	identity.mode = LANPolicyNFQWSDirectMode
	reader := &lanDirectRPDBModel{}
	b.Runtime.Runner = reader
	physicalReads, captures := 0, 0
	b.Runtime.ScopeCheck = func(context.Context, *LANPolicyRuntimePlan) error { physicalReads++; return nil }
	var checks *NetworkPolicyChecks
	gate, err := newNetworkPolicyIdentityAdapter(NetworkPolicyAssemblyOptions{Mode: LANPolicyNFQWSDirectMode, Binding: b, InventoryCheck: func(ctx context.Context, got netidentity.Identity, lan *LANPolicyRuntimePlan) error {
		return checks.InventoryCheck(ctx, got, lan)
	}}, identity)
	if err != nil {
		t.Fatal(err)
	}
	m := New(old.StateRoot)
	consumer.gate = gate
	for _, adapter := range []Adapter{gate, consumer} {
		if err := m.Register(adapter); err != nil {
			t.Fatal(err)
		}
	}
	rows := []BackendInventoryRow{
		{Family: 4, Table: "mangle", Tokens: strings.Fields("-A PREROUTING -m mark --mark 0x1/0xffffffff -j CONNMARK --save-mark")},
		{Family: 6, Table: "mangle", Tokens: strings.Fields("-A PREROUTING -j CONNMARK --restore-mark")},
	}
	image := networkPolicyInventoryTestImage(identity.value, rows)
	checks, err = m.bindNetworkPolicyChecks(gate, func(ctx context.Context, got netidentity.Identity) (BackendInventorySnapshot, error) {
		captures++
		return image, ctx.Err()
	})
	if err != nil {
		t.Fatal(err)
	}
	defer checks.Close()
	plan, _, _ := nfqwsScopedFixture(t)
	plan.PlanID, plan.LAN = "dp-0123456789abcdef", model.plan
	plan.Routes[0].NetworkPolicyRole = "override"
	if err := gate.Stage(context.Background(), plan, root); err != nil || physicalReads != 2 || captures != 4 || reader.reads != 2 {
		t.Fatal("actual opening/closing boundary rejected inert firmware or skipped complete capture", err, physicalReads, captures, reader.reads)
	}
	if err := checks.InventoryCheck(context.Background(), identity.value, nil); err != nil {
		t.Fatal("fixed original direct mode lost after owner absence", err)
	}
	if err := CheckLANPolicyInventory(image, identity.value, nil); err == nil {
		t.Fatal("ordinary legacy absence predicate was relaxed")
	}
	for _, failure := range []string{"coverage", "foreign-nfq", "foreign-gate", "downgrade"} {
		t.Run(failure, func(t *testing.T) {
			original := image
			defer func() { image = original }()
			switch failure {
			case "coverage":
				image.Coverage.RegisteredTablesComplete = false
			case "foreign-nfq":
				image.Rows = append(cloneNetworkPolicyInventoryTestRows(rows), BackendInventoryRow{Family: 6, Table: "raw", Tokens: strings.Fields("-A PREROUTING -j NFQUEUE --queue-num 200")})
			case "foreign-gate":
				image.Rows = append(cloneNetworkPolicyInventoryTestRows(rows), BackendInventoryRow{Family: 4, Table: "vendor_extra", Tokens: []string{"-N", "RZG_foreign"}})
			case "downgrade":
				legacy, err := CompileLANPolicyRuntime(plan.LAN.Generation, plan.LAN.Ingress)
				if err != nil {
					t.Fatal(err)
				}
				if err := gate.Binding.Runtime.Preflight(context.Background(), legacy); err == nil {
					t.Fatal("fixed original participant adopted legacy mode")
				}
				return
			}
			if err := gate.Binding.Runtime.Preflight(context.Background(), plan.LAN); err == nil {
				t.Fatal("whole inventory refusal disappeared", failure)
			}
		})
	}
}
