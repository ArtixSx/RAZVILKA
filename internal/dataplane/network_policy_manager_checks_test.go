package dataplane

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/ArtixSx/razvilka/internal/netidentity"
)

func networkPolicyChecksTestFixture(t *testing.T) (*Manager, Plan, *NetworkPolicyAdapter, *NetworkPolicyChecks, *networkPolicyGateConsumer, *lanPolicyReceiptModel, *int) {
	t.Helper()
	old, p, oldGate, consumer, model := networkPolicyGateManagerFixture(t)
	identity, _ := networkPolicyIdentityFixture()
	var checks *NetworkPolicyChecks
	binding := *oldGate.Binding
	runtime := *binding.Runtime
	runtime.ConsumerCheck = func(ctx context.Context, p *LANPolicyRuntimePlan) error { return checks.ConsumerCheck(ctx, p) }
	binding.Runtime = &runtime
	binding.RetireCheck = func(ctx context.Context, p *LANPolicyRuntimePlan) error { return checks.RetireCheck(ctx, p) }
	gate, err := newNetworkPolicyIdentityAdapter(NetworkPolicyAssemblyOptions{Binding: &binding, InventoryCheck: func(ctx context.Context, identity netidentity.Identity, lan *LANPolicyRuntimePlan) error {
		return checks.InventoryCheck(ctx, identity, lan)
	}}, identity)
	if err != nil {
		t.Fatal(err)
	}
	m := New(old.StateRoot)
	m.FreshProfile = old.FreshProfile
	consumer.gate = gate
	for _, a := range []Adapter{gate, consumer} {
		if err := m.Register(a); err != nil {
			t.Fatal(err)
		}
	}
	reads := 0
	checks, err = m.bindNetworkPolicyChecks(gate, func(ctx context.Context, identity netidentity.Identity) (BackendInventorySnapshot, error) {
		reads++
		var rows []BackendInventoryRow
		for _, family := range []int{4, 6} {
			tool := "iptables"
			if family == 6 {
				tool = "ip6tables"
			}
			data, err := model.Run(ctx, tool, "-t", "mangle", "-S")
			if err != nil {
				return BackendInventorySnapshot{}, err
			}
			for _, line := range strings.Split(string(data), "\n") {
				if line == "" {
					continue
				}
				tokens, err := backendXTablesRowTokens(line)
				if err != nil {
					return BackendInventorySnapshot{}, err
				}
				rows = append(rows, BackendInventoryRow{Family: family, Table: "mangle", Tokens: tokens})
			}
		}
		return networkPolicyInventoryTestImage(identity, rows), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { checks.Close() })
	return m, p, gate, checks, consumer, model, &reads
}

func TestNetworkPolicyChecksActualGateApplyAndStopUseFreshBridge(t *testing.T) {
	m, p, gate, checks, consumer, model, reads := networkPolicyChecksTestFixture(t)
	if x, err := m.Apply(context.Background(), p, nil); err != nil || x.State != "committed" {
		t.Fatal("shared gate apply", x, err)
	}
	if *reads < 4 || len(model.calls) == 0 || !consumer.live {
		t.Fatal("bridge skipped fresh complete captures/effects")
	}
	before := len(model.calls)
	if err := checks.RetireCheck(context.Background(), p.LAN); err == nil || len(model.calls) != before {
		t.Fatal("live consumer acquired delete authority", err)
	}
	if _, err := m.Deactivate(context.Background()); err != nil {
		t.Fatal("consumer-only Stop recursed through Manager/current pending journals", err)
	}
	if err := gate.VerifyRuntimeInactive(context.Background()); err != nil {
		t.Fatal("gate inactive inventory", err)
	}
	for _, count := range model.present {
		if count != 0 {
			t.Fatal("exact acknowledged effect survived Stop")
		}
	}
}

func TestNetworkPolicyChecksUnknownUnusedOwnerRetainsActualGate(t *testing.T) {
	m, p, gate, _, consumer, model, _ := networkPolicyChecksTestFixture(t)
	if _, err := m.Apply(context.Background(), p, nil); err != nil {
		t.Fatal(err)
	}
	// Adding even an unused participant invalidates the frozen registry. A new
	// bridge may include it, but an unknown inactivity observation still refuses.
	unused := &networkPolicyInactiveObserver{fakeAdapter: &fakeAdapter{id: "unused"}, observe: func(context.Context) error { return ErrRuntimeInactivity }}
	if err := m.Register(unused); err != nil {
		t.Fatal(err)
	}
	checks, err := m.bindNetworkPolicyChecks(gate, func(_ context.Context, identity netidentity.Identity) (BackendInventorySnapshot, error) {
		return networkPolicyInventoryTestImage(identity, networkPolicyInventoryLANRows(p.LAN)), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	defer checks.Close()
	consumer.live = false
	gate.Binding.RetireCheck = checks.RetireCheck
	before := len(model.calls)
	if err := gate.Deactivate(context.Background()); err == nil || len(model.calls) != before || unused.calls != 1 {
		t.Fatal("unknown unused owner did not retain gate before first delete", err, unused.calls)
	}
	state, err := gate.readOwner()
	if err != nil || state == nil {
		t.Fatal("unknown consumer lost retained original owner", err)
	}
}

func TestNetworkPolicyChecksRetireSharesHeldOperationWithoutGlobalRecoveryRecursion(t *testing.T) {
	m, p, _, checks, consumer, model, _ := networkPolicyChecksTestFixture(t)
	if err := m.beginOperation(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer m.endOperation()
	if err := os.WriteFile(filepath.Join(m.StateRoot, "latest-execution.json"), []byte(`{"state":"applying"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := checks.RetireCheck(context.Background(), p.LAN); err != nil || consumer.live || len(model.calls) != 0 {
		t.Fatal("current pending operation caused recursive/recovery refusal or mutation", err)
	}
	// The public cold/global check still fences that same journal.
	if err := m.CheckExecutionRecovery(context.Background()); !errors.Is(err, ErrExecutionJournal) {
		t.Fatal("consumer bridge weakened global recovery", err)
	}
}

func TestNetworkPolicyChecksRejectLateRegistryRootIdentityAndCloseChanges(t *testing.T) {
	for _, fault := range []string{"registry", "root", "identity", "binding", "tool", "close", "cancel", "closing-image"} {
		t.Run(fault, func(t *testing.T) {
			m, p, gate, checks, _, model, _ := networkPolicyChecksTestFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			calls := 0
			checks.read = func(_ context.Context, identity netidentity.Identity) (BackendInventorySnapshot, error) {
				calls++
				image := networkPolicyInventoryTestImage(identity, nil)
				if calls == 2 {
					switch fault {
					case "registry":
						if err := m.Register(&networkPolicyInactiveObserver{fakeAdapter: &fakeAdapter{id: "new"}}); err != nil {
							t.Fatal(err)
						}
					case "root":
						m.StateRoot = t.TempDir()
					case "identity":
						gate.identity.value.Inode++
					case "binding":
						copy := *gate.Binding
						gate.Binding = &copy
					case "tool":
						gate.Binding.Runtime.IPTables = "other-iptables"
					case "close":
						checks.Close()
					case "cancel":
						cancel()
					case "closing-image":
						image.Rows = []BackendInventoryRow{{Family: 6, Table: "custom", Tokens: []string{"-P", "INPUT", "ACCEPT"}}}
					}
				}
				return image, nil
			}
			if err := checks.InventoryCheck(ctx, checks.network, p.LAN); err == nil || calls != 2 || len(model.calls) != 0 {
				t.Fatal("late mutation accepted or observation wrote effects", fault, err, calls)
			}
		})
	}
}

func TestNetworkPolicyChecksNilAndUnregisteredDescriptorsRefuse(t *testing.T) {
	var checks *NetworkPolicyChecks
	lan := lanRuntimeFixture(t)
	if checks.RetireCheck(context.Background(), lan) == nil || checks.InventoryCheck(context.Background(), netidentity.Identity{}, lan) == nil || checks.ConsumerCheck(context.Background(), lan) == nil {
		t.Fatal("unbound startup callbacks admitted work")
	}
	m, _, gate, good, _, _, _ := networkPolicyChecksTestFixture(t)
	if _, err := m.BindNetworkPolicyChecks(gate, nil); err == nil {
		t.Fatal("missing concrete collector accepted")
	}
	copy := *gate
	if _, err := m.BindNetworkPolicyChecks(&copy, &BackendInventory{}); err == nil {
		t.Fatal("detached adapter used as registered owner")
	}
	if good.current(nil) == nil {
		t.Fatal("nil operation context accepted")
	}
	if !reflect.DeepEqual(good.adapters, m.Adapters) {
		t.Fatal("fixture changed registry")
	}
}

func TestNetworkPolicyChecksFunctionRunnerIsNotAnImmutableOwner(t *testing.T) {
	_, _, gate, checks, _, _, _ := networkPolicyChecksTestFixture(t)
	old := gate.Binding.Runtime.Runner
	gate.Binding.Runtime.Runner = networkCleanupRunner(func(ctx context.Context, name string, args ...string) ([]byte, error) {
		return old.Run(ctx, name, args...)
	})
	if checks.current(context.Background()) == nil {
		t.Fatal("function-valued replacement acquired original runner identity")
	}
	if sameNetworkPolicyDependency(gate.Binding.Runtime.Runner, gate.Binding.Runtime.Runner) {
		t.Fatal("closure code address supplied stable ownership")
	}
}
