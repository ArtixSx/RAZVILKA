package dataplane

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"
)

// The actual gate compiler, runtime/readback and common receipt run against an
// explicit kernel model. Consumer doubles prove transaction order only.
type networkPolicyGateConsumer struct {
	*fakeAdapter
	gate           *NetworkPolicyAdapter
	live, verified bool
	proof          bool
	err            error
	stopErr        error
}

func (a *networkPolicyGateConsumer) Activate(ctx context.Context, p Plan, root string) error {
	if err := a.gate.Binding.Runtime.Verify(ctx, p.LAN); err != nil {
		return err
	}
	a.live = true
	return a.call("activate")
}
func (a *networkPolicyGateConsumer) Health(context.Context, Plan, string) error { return a.err }
func (a *networkPolicyGateConsumer) Rollback(context.Context, Plan, string) error {
	a.live = false
	return a.call("rollback")
}
func (a *networkPolicyGateConsumer) VerifyRollback(context.Context, Plan, string) (bool, error) {
	a.verified = true
	return a.proof && !a.live, nil
}
func (a *networkPolicyGateConsumer) Deactivate(context.Context) error {
	if a.stopErr != nil {
		return a.stopErr
	}
	a.live = false
	return a.call("deactivate")
}
func (a *networkPolicyGateConsumer) VerifyRuntimeInactive(context.Context) error {
	if a.live {
		return ErrRuntimeInactivity
	}
	return nil
}

func networkPolicyGateManagerFixture(t *testing.T) (*Manager, Plan, *NetworkPolicyAdapter, *networkPolicyGateConsumer, *lanPolicyReceiptModel) {
	t.Helper()
	b, model, root := lanReceiptBindingFixture(t)
	m := New(root)
	m.FreshProfile = func(context.Context) (string, error) { return executionNetwork, nil }
	gate := &NetworkPolicyAdapter{Binding: b, InventoryCheck: func(context.Context) error {
		for _, count := range model.present {
			if count != 0 {
				return ErrRuntimeInactivity
			}
		}
		return nil
	}}
	consumer := &networkPolicyGateConsumer{fakeAdapter: &fakeAdapter{id: "wireguard"}, gate: gate, proof: true}
	b.RetireCheck = func(context.Context, *LANPolicyRuntimePlan) error {
		if consumer.live || !consumer.verified && consumer.rollback {
			return ErrNetworkPolicyConsumers
		}
		return nil
	}
	for _, a := range []Adapter{gate, consumer} {
		if err := m.Register(a); err != nil {
			t.Fatal(err)
		}
	}
	p, err := BuildAt(Input{LAN: model.plan, NetworkProfileID: executionNetwork, Revision: 1, Routes: []Route{{ServiceID: "network-cell", LogicalServiceID: "default", Resolved: "wireguard",
		Sources: []string{"192.168.1.0/24"}, Ingress: []string{"br0"}, CIDRs: []string{"8.8.8.0/24"}, NetworkPolicyGeneration: model.plan.Generation, NetworkPolicyRole: "default"}},
		Engines: []Engine{{ID: NetworkPolicyAdapterID, Installed: true, Configured: true, Activatable: true}, {ID: "wireguard", Installed: true, Configured: true, Activatable: true}},
		Host:    HostState{IPCommand: true, IPTables: true, IP6Tables: true}}, time.Unix(100, 0))
	if err != nil || !p.Ready {
		t.Fatal("gate plan", err, p.Blockers)
	}
	return m, p, gate, consumer, model
}

func TestNetworkPolicyManagerActualGateApplyPromoteStop(t *testing.T) {
	m, p, gate, consumer, model := networkPolicyGateManagerFixture(t)
	committed := false
	execution, err := m.Apply(context.Background(), p, func() (func() error, error) {
		if !consumer.live {
			return nil, ErrNetworkPolicyConsumers
		}
		committed = true
		return func() error { committed = false; return nil }, nil
	})
	if err != nil || execution.State != "committed" || !committed {
		t.Fatal("actual gate transaction", execution, err)
	}
	state, err := gate.readOwner()
	if err != nil || state == nil || !state.Promoted {
		t.Fatal("promoted reference missing", state, err)
	}
	root, _ := gate.receiptRoot(state)
	status, err := gate.Binding.Inspect(context.Background(), state.LAN, root)
	if err != nil || !status.Complete || status.Unknown || status.Promoted {
		t.Fatal("actual promoted receipt", status, err)
	}
	if execution.Steps[0].Adapter != NetworkPolicyAdapterID {
		t.Fatal("gate snapshot was not first")
	}
	var gateAt, consumerAt int
	for i, s := range execution.Steps {
		if s.Phase == "activate" {
			if s.Adapter == NetworkPolicyAdapterID {
				gateAt = i
			} else {
				consumerAt = i
			}
		}
	}
	if gateAt >= consumerAt {
		t.Fatal("consumer activated before gate")
	}
	report, err := m.Deactivate(context.Background())
	if err != nil || report.State != "deactivated" || report.Steps[len(report.Steps)-1].Adapter != NetworkPolicyAdapterID {
		t.Fatal("gate stop order", report, err)
	}
	for _, count := range model.present {
		if count != 0 {
			t.Fatal("gate effect survived Stop")
		}
	}
	if err := m.VerifyRuntimeInactive(context.Background()); err != nil {
		t.Fatal("fresh model inactivity", err)
	}
}

func TestNetworkPolicyManagerActualGateRollbackWaitsForReadback(t *testing.T) {
	for _, proof := range []bool{true, false} {
		t.Run(map[bool]string{true: "verified", false: "unknown"}[proof], func(t *testing.T) {
			m, p, gate, consumer, model := networkPolicyGateManagerFixture(t)
			consumer.err = errors.New("consumer health failed")
			consumer.proof = proof
			x, err := m.Apply(context.Background(), p, nil)
			if err == nil || !consumer.verified {
				t.Fatal("failure or independent readback missing", x, err)
			}
			if proof {
				if x.State != "rolled-back" || !x.RollbackVerified {
					t.Fatal("verified rollback", x, err)
				}
				state, _ := gate.readOwner()
				if state != nil {
					t.Fatal("removed gate owner remained")
				}
				for _, count := range model.present {
					if count != 0 {
						t.Fatal("known effects not cleaned")
					}
				}
			} else {
				if x.State != "rollback-failed" || x.RollbackVerified || !errors.Is(err, ErrNetworkPolicyConsumers) {
					t.Fatal("unknown consumer was not fenced", x, err)
				}
				state, _ := gate.readOwner()
				if state == nil {
					t.Fatal("negative boundary lost")
				}
				for _, count := range model.present {
					if count != 1 {
						t.Fatal("unknown consumer granted gate deletion")
					}
				}
				if err := m.CheckExecutionRecovery(context.Background()); !errors.Is(err, ErrExecutionJournal) {
					t.Fatal("unknown rollback not retained as recovery fence", err)
				}
			}
		})
	}
}

func TestNetworkPolicyManagerGateRequiresParticipationBeforeJournal(t *testing.T) {
	m, p, _, _, model := networkPolicyGateManagerFixture(t)
	p.Adapters = slices.DeleteFunc(p.Adapters, func(id string) bool { return id == NetworkPolicyAdapterID })
	if _, err := m.Apply(context.Background(), p, nil); !errors.Is(err, ErrLANPolicyRuntime) {
		t.Fatal("missing gate participant accepted", err)
	}
	if len(model.calls) != 0 {
		t.Fatal("refusal performed kernel effects")
	}
	if _, err := os.Stat(filepath.Join(m.StateRoot, "latest-execution.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("refusal published applying journal", err)
	}
	p.LAN = nil
	if _, err := m.Apply(context.Background(), p, nil); err == nil {
		t.Fatal("scalar generation granted effect authority")
	}
}

func TestNetworkPolicyManagerGateRefusesReplacementWithoutMutation(t *testing.T) {
	m, p, _, _, model := networkPolicyGateManagerFixture(t)
	if _, err := m.Apply(context.Background(), p, nil); err != nil {
		t.Fatal(err)
	}
	before := len(model.calls)
	p.PlanID += "-next"
	x, err := m.Apply(context.Background(), p, nil)
	if !errors.Is(err, ErrNetworkPolicyReplacement) || x.State != "canary-failed" || len(model.calls) != before {
		t.Fatal("replacement bypassed required cutover", x, err)
	}
}

func TestNetworkPolicyManagerGateLostAcknowledgementAndPromotionFence(t *testing.T) {
	for _, fault := range []string{"add", "promotion"} {
		t.Run(fault, func(t *testing.T) {
			m, p, gate, _, model := networkPolicyGateManagerFixture(t)
			if fault == "add" {
				model.lostAdd = 0
			} else {
				gate.Binding.options.fault = func(point string, _ int) error {
					if point == "promotion-intent" {
						return errors.New("model power loss during promotion")
					}
					return nil
				}
			}
			x, err := m.Apply(context.Background(), p, nil)
			if err == nil || x.State != "rollback-failed" || x.RollbackVerified {
				t.Fatal("unknown outcome granted success", x, err)
			}
			state, _ := gate.readOwner()
			if state == nil {
				t.Fatal("typed pending/promotion reference lost")
			}
			before := len(model.calls)
			p.PlanID += "-retry"
			if _, err := m.Apply(context.Background(), p, nil); !errors.Is(err, ErrExecutionJournal) || len(model.calls) != before {
				t.Fatal("unknown addition was replayed", err)
			}
		})
	}
}

func TestNetworkPolicyManagerGateCannotDisappearInLegacyPlan(t *testing.T) {
	m, p, _, _, model := networkPolicyGateManagerFixture(t)
	if _, err := m.Apply(context.Background(), p, nil); err != nil {
		t.Fatal(err)
	}
	legacy, err := BuildAt(Input{Revision: 2, Routes: []Route{{ServiceID: "service", Resolved: "direct"}}}, time.Unix(101, 0))
	if err != nil {
		t.Fatal(err)
	}
	before := len(model.calls)
	if _, err := m.Apply(context.Background(), legacy, nil); !errors.Is(err, ErrNetworkPolicyReplacement) || len(model.calls) != before {
		t.Fatal("live gate was omitted without exact inactivity", err)
	}
	if _, err := m.Deactivate(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Apply(context.Background(), legacy, nil); err != nil {
		t.Fatal("verified stopped gate could not return to baseline", err)
	}
}

func TestNetworkPolicyManagerGateStopFailureRetainsBoundary(t *testing.T) {
	m, p, gate, consumer, model := networkPolicyGateManagerFixture(t)
	if _, err := m.Apply(context.Background(), p, nil); err != nil {
		t.Fatal(err)
	}
	consumer.stopErr = errors.New("unknown process termination")
	before := len(model.calls)
	report, err := m.Deactivate(context.Background())
	if err == nil || report.State != "degraded" || len(model.calls) != before {
		t.Fatal("failed consumer allowed gate retirement", report, err)
	}
	state, _ := gate.readOwner()
	if state == nil {
		t.Fatal("unknown Stop lost typed gate reference")
	}
}

func TestNetworkPolicyManagerGateRecoveryCannotStartAfterGateRefusal(t *testing.T) {
	for _, change := range []string{"boot", "network"} {
		t.Run(change, func(t *testing.T) {
			m, p, gate, consumer, model := networkPolicyGateManagerFixture(t)
			if _, err := m.Apply(context.Background(), p, nil); err != nil {
				t.Fatal(err)
			}
			before := len(model.calls)
			if change == "boot" {
				gate.Binding.options.boot = func() (string, error) { return "new-model-boot", nil }
			} else {
				m.FreshProfile = func(context.Context) (string, error) { return "wan-abcdef012345", nil }
			}
			recovery, err := m.Recover(context.Background())
			if err == nil || consumer.recovered || len(model.calls) != before {
				t.Fatal("stale admission restored consumer", recovery, err)
			}
		})
	}
}
