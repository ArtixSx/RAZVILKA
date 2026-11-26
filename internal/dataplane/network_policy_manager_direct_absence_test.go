package dataplane

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/ArtixSx/razvilka/internal/netidentity"
)

type networkPolicyDirectAbsenceModel struct {
	cleanup, retired, captures, absence, rpdbReads int
	refuse                                         string
	rpdb                                           string
	live                                           bool
}

func (m *networkPolicyDirectAbsenceModel) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	if name != "ip" || len(args) != 4 || args[0] != "-4" && args[0] != "-6" || args[1] != "-N" || args[2] != "rule" || args[3] != "show" {
		return nil, errors.New("absence attempted an effect or incomplete read")
	}
	m.rpdbReads++
	return []byte(m.rpdb), ctx.Err()
}

// Actual typed registered gate, original callbacks, owned owner journal and
// complete inventory predicate. Physical/kernel/process leaves are models.
func networkPolicyDirectAbsenceFixture(t *testing.T) (*NetworkPolicyAdapter, Plan, *networkPolicyDirectAbsenceModel) {
	t.Helper()
	b, lanModel, _ := lanDirectReceiptFixture(t)
	model := &networkPolicyDirectAbsenceModel{rpdb: "0: from all lookup 255\n32766: from all lookup 254\n32767: from all lookup 253\n"}
	b.Runtime.Runner = model
	b.Runtime.ScopeCheck = func(context.Context, *LANPolicyRuntimePlan) error { return ErrReviewChanged }
	b.ApplyGuard = func(context.Context, *LANPolicyRuntimePlan, LANPolicyEffect) error { return ErrReviewChanged }
	b.CleanupGuard = func(ctx context.Context, lan *LANPolicyRuntimePlan, _ LANPolicyEffect) error {
		model.cleanup++
		if !reflect.DeepEqual(lan, lanModel.plan) || model.refuse == "cleanup-open" || model.refuse == "cleanup-close" && model.cleanup == 2 {
			return ErrReviewChanged
		}
		return ctx.Err()
	}
	b.RetireCheck = func(ctx context.Context, lan *LANPolicyRuntimePlan) error {
		model.retired++
		if !reflect.DeepEqual(lan, lanModel.plan) || model.live || model.refuse == "retire" {
			return ErrNetworkPolicyConsumers
		}
		return ctx.Err()
	}
	identity, _ := networkPolicyIdentityFixture()
	identity.mode = LANPolicyNFQWSDirectMode
	var checks *NetworkPolicyChecks
	gate, err := newNetworkPolicyIdentityAdapter(NetworkPolicyAssemblyOptions{Mode: LANPolicyNFQWSDirectMode, Binding: b,
		InventoryCheck: func(ctx context.Context, got netidentity.Identity, lan *LANPolicyRuntimePlan) error {
			if lan == nil {
				model.absence++
				if model.refuse == "absence" {
					return ErrBackendInventoryUnknown
				}
			}
			return checks.InventoryCheck(ctx, got, lan)
		}}, identity)
	if err != nil {
		t.Fatal(err)
	}
	m := New(privateScopedXrayFixtureDir(t))
	consumer := &networkPolicyGateConsumer{fakeAdapter: &fakeAdapter{id: "nfqws2"}, gate: gate, proof: true}
	for _, adapter := range []Adapter{gate, consumer} {
		if err := m.Register(adapter); err != nil {
			t.Fatal(err)
		}
	}
	checks, err = m.bindNetworkPolicyChecks(gate, func(ctx context.Context, got netidentity.Identity) (BackendInventorySnapshot, error) {
		model.captures++
		image := networkPolicyInventoryTestImage(got, nil)
		switch model.refuse {
		case "coverage":
			image.Coverage.RegisteredTablesComplete = false
		case "foreign":
			image.Rows = []BackendInventoryRow{{Family: 6, Table: "raw", Tokens: strings.Fields("-A PREROUTING -j NFQUEUE --queue-num 201")}}
		}
		return image, ctx.Err()
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { checks.Close() })
	plan, _, _ := nfqwsScopedFixture(t)
	plan.PlanID, plan.LAN = "dp-0123456789abcdef", lanModel.plan
	plan.Routes[0].NetworkPolicyRole = "override"
	return gate, plan, model
}

func TestNetworkPolicyDirectAbsentOwnerRequiresFreshCleanupAndInventory(t *testing.T) {
	gate, plan, model := networkPolicyDirectAbsenceFixture(t)
	for i := 0; i < 2; i++ {
		ok, err := gate.VerifyRollback(context.Background(), plan, "")
		if err != nil || !ok || model.cleanup != 2*(i+1) || model.retired != i+1 || model.absence != i+1 || model.captures != 8*(i+1) || model.rpdbReads != 2*(i+1) {
			t.Fatal("absent owner skipped fresh retained cleanup/consumer/full inventory", ok, err, model)
		}
	}
}

func TestNetworkPolicyDirectAbsentOwnerRefusesUnsettledOrForeignState(t *testing.T) {
	for _, failure := range []string{"retire", "absence", "coverage", "foreign", "rpdb", "cleanup-close"} {
		t.Run(failure, func(t *testing.T) {
			gate, plan, model := networkPolicyDirectAbsenceFixture(t)
			model.refuse = failure
			if failure == "rpdb" {
				model.rpdb = "73: from all lookup 254\n"
			}
			if ok, err := gate.VerifyRollback(context.Background(), plan, ""); err == nil || ok {
				t.Fatal("owner absence falsely verified unsettled namespace", ok, err)
			}
		})
	}
	gate, plan, model := networkPolicyDirectAbsenceFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if ok, err := gate.VerifyRollback(ctx, plan, ""); ok || !errors.Is(err, context.Canceled) || model.cleanup != 0 || model.captures != 0 {
		t.Fatal("canceled read supplied absence", ok, err, model)
	}
}

func TestNetworkPolicyDirectMissingReceiptRetainsExactOwnerOnRefusal(t *testing.T) {
	for _, failure := range []string{"cleanup-open", "retire", "absence", "coverage", "foreign", "rpdb", "cleanup-close"} {
		t.Run(failure, func(t *testing.T) {
			gate, plan, model := networkPolicyDirectAbsenceFixture(t)
			state, err := gate.gateFor(plan)
			if err != nil || writeNetworkPolicyGate(gate.ownerPath(), state) != nil {
				t.Fatal(err)
			}
			model.refuse = failure
			if failure == "rpdb" {
				model.rpdb = "73: from all lookup 254\n"
			}
			if err := gate.Rollback(context.Background(), plan, ""); err == nil {
				t.Fatal("missing receipt cleared owner without fresh absence", failure)
			}
			got, err := gate.readOwner()
			if err != nil || !reflect.DeepEqual(got, state) {
				t.Fatal("refusal lost exact original intent", got, err)
			}
			if ok, _ := gate.VerifyRollback(context.Background(), plan, ""); ok {
				t.Fatal("retained owner falsely verified rollback")
			}
		})
	}
}

func TestNetworkPolicyDirectMissingReceiptClearsOnlyObservedAbsence(t *testing.T) {
	gate, plan, model := networkPolicyDirectAbsenceFixture(t)
	state, err := gate.gateFor(plan)
	if err != nil || writeNetworkPolicyGate(gate.ownerPath(), state) != nil {
		t.Fatal(err)
	}
	model.live = true
	if err := gate.Rollback(context.Background(), plan, ""); !errors.Is(err, ErrNetworkPolicyConsumers) {
		t.Fatal("live consumer settled through missing COMMON receipt", err)
	}
	model.live = false
	if err := gate.Rollback(context.Background(), plan, ""); err != nil {
		t.Fatal("legitimate retained cleanup borrowed expired forward review", err)
	}
	got, err := gate.readOwner()
	if err != nil || got != nil {
		t.Fatal("observed absence did not settle exact owner", got, err)
	}
	if ok, err := gate.VerifyRollback(context.Background(), plan, ""); err != nil || !ok {
		t.Fatal("fresh independent absence did not verify", ok, err)
	}
}
