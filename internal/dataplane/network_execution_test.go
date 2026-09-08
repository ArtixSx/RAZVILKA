package dataplane

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/engineconfig"
	"github.com/ArtixSx/razvilka/internal/evidence"
)

const executionNetwork = "wan-0123456789ab"

type networkExecutionAdapter struct {
	*fakeAdapter
	after func(string) error
}

func (a *networkExecutionAdapter) phase(name string) error {
	if err := a.call(name); err != nil {
		return err
	}
	if a.after != nil {
		return a.after(name)
	}
	return nil
}
func (a *networkExecutionAdapter) Snapshot(context.Context, Plan, string) error {
	return a.phase("snapshot")
}
func (a *networkExecutionAdapter) Stage(context.Context, Plan, string) error {
	return a.phase("stage")
}
func (a *networkExecutionAdapter) Validate(context.Context, Plan, string) error {
	return a.phase("validate")
}
func (a *networkExecutionAdapter) Canary(context.Context, RoutePlan, string) error {
	return a.phase("canary")
}
func (a *networkExecutionAdapter) Activate(context.Context, Plan, string) error {
	return a.phase("activate")
}
func (a *networkExecutionAdapter) Health(context.Context, Plan, string) error {
	return a.phase("health")
}
func (a *networkExecutionAdapter) Commit(context.Context, Plan, string) error {
	return a.phase("commit-adapter")
}
func (a *networkExecutionAdapter) Reconcile(context.Context, Plan) error {
	return a.phase("reconcile")
}
func (a *networkExecutionAdapter) RefreshPolicy(context.Context, Plan) (bool, error) {
	return true, a.phase("refresh")
}

func networkExecutionPlan() Plan {
	route := "sing-box:" + checkedNodeID
	return Plan{
		SchemaVersion: SchemaVersion, PlanID: "dp-network-execution", Digest: strings.Repeat("a", 64), Revision: 1, Ready: true,
		NetworkProfileID: executionNetwork, Adapters: []string{"sing-box"}, RequiredEvidence: evidence.Service,
		Routes:        []Route{{ServiceID: "telegram", Selected: route, Resolved: route, Domains: []string{"telegram.org"}, ProbeURL: "https://telegram.org/"}},
		RouteEvidence: []RouteEvidence{{ServiceID: "telegram", Route: route, Required: evidence.Service}},
	}
}

func TestNetworkChangeStopsApplyBeforeLiveOrRollsBackAfterLive(t *testing.T) {
	for _, phase := range []string{"initial", "snapshot", "stage", "validate", "canary", "activate", "health", "commit-adapter", "config-commit"} {
		t.Run(phase, func(t *testing.T) {
			manager := New(t.TempDir())
			profile := executionNetwork
			manager.FreshProfile = func(context.Context) (string, error) { return profile, nil }
			adapter := &networkExecutionAdapter{fakeAdapter: &fakeAdapter{id: "sing-box"}, after: func(current string) error {
				if current == phase {
					profile = "wan-ffffffffffff"
				}
				return nil
			}}
			if err := manager.Register(adapter); err != nil {
				t.Fatal(err)
			}
			plan := networkExecutionPlan()
			previous := plan
			previous.PlanID, previous.State = "dp-previous-network", "committed"
			if err := manager.Record(previous); err != nil {
				t.Fatal(err)
			}
			journal := filepath.Join(manager.StateRoot, "latest-committed-plan.json")
			before, err := os.ReadFile(journal)
			if err != nil {
				t.Fatal(err)
			}
			if phase == "initial" {
				profile = "wan-ffffffffffff"
			}
			committed := false
			execution, err := manager.Apply(context.Background(), plan, func() (func() error, error) {
				committed = true
				if phase == "config-commit" {
					profile = "wan-ffffffffffff"
				}
				return func() error { committed = false; return nil }, nil
			})
			live := phase == "activate" || phase == "health" || phase == "commit-adapter" || phase == "config-commit"
			wantState := "network-stale"
			if live {
				wantState = "rolled-back"
			}
			if !errors.Is(err, ErrNetworkChanged) || committed || execution.State != wantState || adapter.rollback != live {
				t.Fatalf("phase=%s state=%s calls=%v committed=%t err=%v", phase, execution.State, adapter.calls, committed, err)
			}
			after, err := os.ReadFile(journal)
			if err != nil || !bytes.Equal(before, after) {
				t.Fatalf("failed network transaction overwrote committed history: %v", err)
			}
		})
	}
}

func TestNetworkChangeWhileWaitingForApplyGateRunsNoAdapter(t *testing.T) {
	manager := New(t.TempDir())
	profile := executionNetwork
	manager.FreshProfile = func(context.Context) (string, error) { return profile, nil }
	adapter := &networkExecutionAdapter{fakeAdapter: &fakeAdapter{id: "sing-box"}}
	if err := manager.Register(adapter); err != nil {
		t.Fatal(err)
	}
	if err := manager.beginOperation(context.Background()); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, err := manager.Apply(context.Background(), networkExecutionPlan(), nil); done <- err }()
	profile = "wan-ffffffffffff"
	manager.endOperation()
	if err := <-done; !errors.Is(err, ErrNetworkChanged) || len(adapter.calls) != 0 {
		t.Fatalf("waiting plan retained authority: calls=%v err=%v", adapter.calls, err)
	}
}

func TestCanceledNodeApplyDoesNotRollbackBeforeLiveMutation(t *testing.T) {
	for _, phase := range []string{"snapshot", "stage", "canary", "activate"} {
		for _, deadline := range []bool{false, true} {
			t.Run(phase+map[bool]string{false: "/canceled", true: "/deadline"}[deadline], func(t *testing.T) {
				manager := New(t.TempDir())
				manager.FreshProfile = func(context.Context) (string, error) { return executionNetwork, nil }
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				adapter := &networkExecutionAdapter{fakeAdapter: &fakeAdapter{id: "sing-box"}, after: func(current string) error {
					if current != phase {
						return nil
					}
					if deadline {
						return context.DeadlineExceeded
					}
					cancel()
					return nil
				}}
				if err := manager.Register(adapter); err != nil {
					t.Fatal(err)
				}
				plan := networkExecutionPlan()
				plan.ObservedEvidence, plan.RouteEvidence[0].Observed = evidence.Service, evidence.Service
				execution, err := manager.Apply(ctx, plan, nil)
				wantErr := context.Canceled
				if deadline {
					wantErr = context.DeadlineExceeded
				}
				live := phase == "activate"
				wantState := "canary-failed"
				if live {
					wantState = "rolled-back"
				}
				if !errors.Is(err, wantErr) || execution.State != wantState || adapter.rollback != live {
					t.Fatalf("canceled apply touched wrong lifecycle: state=%s calls=%v err=%v", execution.State, adapter.calls, err)
				}
				if !live && strings.Contains(strings.Join(adapter.calls, ","), "activate") {
					t.Fatalf("canceled candidate activated runtime: %v", adapter.calls)
				}
				status, err := manager.Status()
				if err != nil || status.Plan == nil || status.Plan.ObservedEvidence != evidence.None || status.Plan.RouteEvidence[0].Observed != evidence.None {
					t.Fatalf("canceled candidate retained evidence: %+v err=%v", status.Plan, err)
				}
			})
		}
	}
}

func TestActivationNetworkPreflightDoesNotRollbackUntouchedRuntime(t *testing.T) {
	manager := New(t.TempDir())
	manager.FreshProfile = func(context.Context) (string, error) { return executionNetwork, nil }
	adapter := &networkExecutionAdapter{fakeAdapter: &fakeAdapter{id: "sing-box"}, after: func(phase string) error {
		if phase == "activate" {
			return preflightRefusalError{ErrNetworkChanged}
		}
		return nil
	}}
	if err := manager.Register(adapter); err != nil {
		t.Fatal(err)
	}
	execution, err := manager.Apply(context.Background(), networkExecutionPlan(), nil)
	if !errors.Is(err, ErrNetworkChanged) || execution.State != "network-stale" || adapter.rollback {
		t.Fatalf("preflight rejection rolled back working runtime: state=%s calls=%v err=%v", execution.State, adapter.calls, err)
	}
}

func TestStaleNodeRecoveryAndRefreshPreserveRuntimeAndHistory(t *testing.T) {
	for _, tc := range []struct{ name, stored, current string }{
		{"empty-current", executionNetwork, ""},
		{"unknown-current", executionNetwork, "network-unknown"},
		{"changed-current", executionNetwork, "wan-ffffffffffff"},
		{"legacy-missing-epoch", "", executionNetwork},
		{"legacy-unknown-epoch", "network-unknown", executionNetwork},
	} {
		t.Run(tc.name, func(t *testing.T) {
			manager := New(t.TempDir())
			manager.FreshProfile = func(context.Context) (string, error) { return tc.current, nil }
			node := &networkExecutionAdapter{fakeAdapter: &fakeAdapter{id: "sing-box"}}
			other := &fakeAdapter{id: "nfqws2"}
			for _, adapter := range []Adapter{node, other} {
				if err := manager.Register(adapter); err != nil {
					t.Fatal(err)
				}
			}
			plan := networkExecutionPlan()
			plan.NetworkProfileID = tc.stored
			plan.State, plan.Adapters = "committed", []string{"nfqws2", "sing-box"}
			if err := manager.Record(plan); err != nil {
				t.Fatal(err)
			}
			before, err := os.ReadFile(filepath.Join(manager.StateRoot, "latest-committed-plan.json"))
			if err != nil {
				t.Fatal(err)
			}
			if err := manager.writeRecoveryLocked(Recovery{PlanID: plan.PlanID, State: "degraded", FailureCount: 1}); err != nil {
				t.Fatal(err)
			}
			for range 2 {
				recovery, err := manager.Recover(context.Background())
				if !errors.Is(err, ErrNetworkChanged) || recovery.State != "network-stale" || recovery.Guarded || recovery.FailureCount != 0 {
					t.Fatalf("stale recovery activated boot-loop guard: %+v err=%v", recovery, err)
				}
			}
			if changed, err := manager.RefreshCommitted(context.Background()); !errors.Is(err, ErrNetworkChanged) || len(changed) != 0 {
				t.Fatalf("stale plan refreshed policy: changed=%v err=%v", changed, err)
			}
			status, err := manager.Status()
			if err != nil || status.PolicyRefresh == nil || status.PolicyRefresh.State != "network-stale" || len(node.calls) != 0 || len(other.calls) != 0 {
				t.Fatalf("stale recovery touched runtime or lost status: node=%v other=%v status=%+v err=%v", node.calls, other.calls, status.PolicyRefresh, err)
			}
			after, err := os.ReadFile(filepath.Join(manager.StateRoot, "latest-committed-plan.json"))
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("stale recovery modified committed history")
			}
		})
	}
}

func TestNetworkChangeBetweenRecoveryAdaptersDoesNotDeactivateOtherRuntime(t *testing.T) {
	for _, operation := range []string{"reconcile", "refresh"} {
		t.Run(operation, func(t *testing.T) {
			manager := New(t.TempDir())
			profile := executionNetwork
			manager.FreshProfile = func(context.Context) (string, error) { return profile, nil }
			node := &networkExecutionAdapter{fakeAdapter: &fakeAdapter{id: "sing-box"}, after: func(phase string) error {
				if phase == operation {
					profile = "wan-ffffffffffff"
				}
				return nil
			}}
			other := &fakeAdapter{id: "nfqws2"}
			for _, adapter := range []Adapter{node, other} {
				if err := manager.Register(adapter); err != nil {
					t.Fatal(err)
				}
			}
			plan := networkExecutionPlan()
			plan.State, plan.Adapters = "committed", []string{"sing-box", "nfqws2"}
			if err := manager.Record(plan); err != nil {
				t.Fatal(err)
			}
			var err error
			if operation == "reconcile" {
				_, err = manager.Recover(context.Background())
			} else {
				_, err = manager.RefreshCommitted(context.Background())
			}
			if !errors.Is(err, ErrNetworkChanged) || len(other.calls) != 0 || len(node.calls) != 1 || node.calls[0] != operation {
				t.Fatalf("late stale recovery touched another runtime: node=%v other=%v err=%v", node.calls, other.calls, err)
			}
		})
	}
}

func TestNodeProxyMaterializesOnlyThePlanNetwork(t *testing.T) {
	for _, changed := range []bool{false, true} {
		t.Run(map[bool]string{false: "stable", true: "during-materialization"}[changed], func(t *testing.T) {
			root := t.TempDir()
			configs := engineconfig.New(filepath.Join(root, "stage"), filepath.Join(root, "backup"))
			adapter, err := NewProxyTunnelAdapter("sing-box", configs, filepath.Join(root, "state"))
			if err != nil {
				t.Fatal(err)
			}
			processes := &proxyFakeProcesses{running: map[string]bool{}}
			adapter.Processes = processes
			adapter.Runner = &proxyFakeRunner{processes: processes, iface: adapter.Interface}
			adapter.EngineBin, adapter.SidecarBin, adapter.IP = "sing-box", "sing-box", "ip"
			adapter.IPTables, adapter.IP6Tables = "iptables", "ip6tables"
			adapter.Resolver = func(context.Context, string) ([]netip.Addr, error) {
				return []netip.Addr{netip.MustParseAddr("203.0.113.9")}, nil
			}
			profile := executionNetwork
			adapter.FreshProfile = func(context.Context) (string, error) { return profile, nil }
			called := false
			adapter.NodeRoutes = func(_ context.Context, requests []NodeRouteRequest, got string, _ time.Time) (NodeRouteMaterial, error) {
				called = true
				if got != executionNetwork || len(requests) != 1 || requests[0].NodeID != checkedNodeID {
					t.Fatalf("materializer received another identity: profile=%q requests=%+v", got, requests)
				}
				if changed {
					profile = "wan-ffffffffffff"
				}
				return NodeRouteMaterial{Config: []byte(`{"outbounds":[{"type":"vless","tag":"proxy","server":"node.example","server_port":443}],"route":{"final":"proxy"}}`)}, nil
			}
			transaction := filepath.Join(root, "transaction")
			plan := networkExecutionPlan()
			plan.Routes[0].Sources = []string{"192.168.1.25/32"}
			if err := adapter.Snapshot(context.Background(), plan, transaction); err != nil {
				t.Fatal(err)
			}
			err = adapter.Stage(context.Background(), plan, transaction)
			if !called || changed && !errors.Is(err, ErrNetworkChanged) || !changed && err != nil {
				t.Fatalf("changed=%t called=%t err=%v", changed, called, err)
			}
			if changed && regularFile(filepath.Join(transaction, "engine.staged.json")) {
				t.Fatal("a changed network produced a staged candidate")
			}
			profile = "wan-ffffffffffff"
			if err := adapter.Reconcile(context.Background(), plan); !errors.Is(err, ErrNetworkChanged) {
				t.Fatalf("stale node runtime reconciled: %v", err)
			}
			if _, err := adapter.RefreshPolicy(context.Background(), plan); !errors.Is(err, ErrNetworkChanged) {
				t.Fatalf("stale node policy refreshed: %v", err)
			}
			if err := adapter.Activate(context.Background(), plan, transaction); !errors.Is(err, ErrNetworkChanged) || len(processes.startSpecs) != 0 {
				t.Fatalf("stale candidate started a process: %v", err)
			}
		})
	}
}

type networkCleanupRunner func(context.Context, string, ...string) ([]byte, error)

func (run networkCleanupRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	return run(ctx, name, args...)
}

func networkCleanupProxy(t *testing.T) (*ProxyTunnelAdapter, *proxyFakeProcesses, PolicyState) {
	t.Helper()
	root := t.TempDir()
	adapter, err := NewProxyTunnelAdapter("sing-box", engineconfig.New(filepath.Join(root, "stage"), filepath.Join(root, "backup")), filepath.Join(root, "state"))
	if err != nil {
		t.Fatal(err)
	}
	processes := &proxyFakeProcesses{running: map[string]bool{}}
	adapter.Processes = processes
	adapter.Runner = &proxyFakeRunner{processes: processes, iface: adapter.Interface}
	adapter.EngineBin, adapter.SidecarBin, adapter.IP = "sing-box", "sing-box", "ip"
	adapter.IPTables, adapter.IP6Tables = "iptables", "ip6tables"
	adapter.FreshProfile = func(context.Context) (string, error) { return executionNetwork, nil }
	adapter.SOCKSProbe = func(context.Context, string) error { return nil }
	adapter.Probe = func(context.Context, string) error { return nil }
	adapter.ServiceIPProbe = func(context.Context, string, string, netip.Addr) error { return nil }
	adapter.Resolver = func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("203.0.113.9")}, nil
	}
	old := PolicyState{Interface: adapter.Interface, Table: adapter.Table, PriorityBase: adapter.Priority, Prefixes: []string{"198.51.100.8/32"}}
	data, _ := json.MarshalIndent(old, "", "  ")
	for path, contents := range map[string][]byte{adapter.policyPath(): data, adapter.engineConfigPath(): []byte(`{}`), adapter.sidecarConfigPath(): []byte(`{}`)} {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, contents, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return adapter, processes, old
}

func TestCanceledNodePolicyRefreshRestoresWithIndependentContext(t *testing.T) {
	for _, failRollback := range []bool{false, true} {
		t.Run(map[bool]string{false: "restored", true: "rollback-error-preserved"}[failRollback], func(t *testing.T) {
			adapter, processes, old := networkCleanupProxy(t)
			processes.running["sing-box-engine"], processes.running["sing-box-tun"] = true, true
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			rollbackFailure := errors.New("policy rollback failed")
			restoreAttempted := false
			baseRunner := adapter.Runner
			adapter.Runner = networkCleanupRunner(func(runCtx context.Context, name string, args ...string) ([]byte, error) {
				if err := runCtx.Err(); err != nil {
					return nil, err
				}
				command := strings.Join(args, " ")
				if ctx.Err() != nil {
					if _, bounded := runCtx.Deadline(); !bounded {
						t.Fatal("policy cleanup has no deadline")
					}
					if strings.Contains(command, "rule add") && strings.Contains(command, old.Prefixes[0]) {
						restoreAttempted = true
						if failRollback {
							return nil, rollbackFailure
						}
					}
				} else if strings.Contains(command, "rule add") && strings.Contains(command, "203.0.113.9/32") {
					cancel() // The new rule exists before health notices cancellation.
				}
				return baseRunner.Run(runCtx, name, args...)
			})
			plan := networkExecutionPlan()
			plan.Routes[0].Sources = []string{"192.168.1.25/32"}
			updated, err := adapter.RefreshPolicy(ctx, plan)
			if updated || !errors.Is(err, context.Canceled) || !restoreAttempted || errors.Is(err, rollbackFailure) != failRollback {
				t.Fatalf("canceled refresh lost rollback: updated=%t restored=%t err=%v", updated, restoreAttempted, err)
			}
			stored, exists, readErr := adapter.loadPolicy()
			if readErr != nil || !exists || !samePolicy(stored, old) {
				t.Fatalf("canceled refresh changed committed policy: %+v err=%v", stored, readErr)
			}
		})
	}
}

type networkCancelOnSidecar struct {
	*proxyFakeProcesses
	parent  context.Context
	cancel  context.CancelFunc
	cleaned []string
}

func (p *networkCancelOnSidecar) Start(ctx context.Context, spec ProcessSpec) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := p.proxyFakeProcesses.Start(ctx, spec); err != nil {
		return err
	}
	if spec.ID == "sing-box-tun" {
		p.cancel()
	}
	return nil
}

func (p *networkCancelOnSidecar) Stop(ctx context.Context, spec ProcessSpec) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if p.parent.Err() != nil {
		if _, bounded := ctx.Deadline(); !bounded {
			return errors.New("process cleanup has no deadline")
		}
		p.cleaned = append(p.cleaned, spec.ID)
	}
	return p.proxyFakeProcesses.Stop(ctx, spec)
}

func TestCanceledNodeRecoveryCleansOnlyRuntimeItRestarted(t *testing.T) {
	for _, preflight := range []bool{false, true} {
		t.Run(map[bool]string{false: "after-sidecar-start", true: "before-restart"}[preflight], func(t *testing.T) {
			adapter, baseProcesses, _ := networkCleanupProxy(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			processes := &networkCancelOnSidecar{proxyFakeProcesses: baseProcesses, parent: ctx, cancel: cancel}
			adapter.Processes = processes
			baseRunner := adapter.Runner
			adapter.Runner = networkCleanupRunner(func(runCtx context.Context, name string, args ...string) ([]byte, error) {
				if err := runCtx.Err(); err != nil {
					return nil, err
				}
				return baseRunner.Run(runCtx, name, args...)
			})
			manager := New(t.TempDir())
			manager.FreshProfile = adapter.FreshProfile
			other := &fakeAdapter{id: "nfqws2"}
			for _, registered := range []Adapter{adapter, other} {
				if err := manager.Register(registered); err != nil {
					t.Fatal(err)
				}
			}
			plan := networkExecutionPlan()
			plan.State, plan.Adapters = "committed", []string{"sing-box", "nfqws2"}
			if err := manager.Record(plan); err != nil {
				t.Fatal(err)
			}
			if preflight {
				processes.running["sing-box-engine"], processes.running["sing-box-tun"] = true, true
				cancel()
			}
			_, err := manager.Recover(ctx)
			if !errors.Is(err, context.Canceled) || len(other.calls) != 0 {
				t.Fatalf("canceled recovery touched another adapter: calls=%v err=%v", other.calls, err)
			}
			if preflight {
				if len(processes.running) != 2 || len(processes.cleaned) != 0 || len(processes.startSpecs) != 0 {
					t.Fatalf("preflight cancellation touched running processes: %+v", processes)
				}
			} else if len(processes.running) != 0 || len(processes.cleaned) != 2 || len(processes.startSpecs) != 2 {
				t.Fatalf("canceled restart left owned processes: %+v", processes)
			}
		})
	}
}

func TestNodeRollbackDoesNotWriteAnUnchangedGlobalEngineConfig(t *testing.T) {
	adapter, _, _ := networkCleanupProxy(t)
	root := t.TempDir()
	global := filepath.Join(t.TempDir(), "global-engine.json")
	if err := os.WriteFile(global, []byte("new external config"), 0o600); err != nil {
		t.Fatal(err)
	}
	snapshot := proxySnapshot{ConfigPath: global, Config: []byte("old config at snapshot"), ConfigExisted: true, ConfigDraft: false}
	data, _ := json.Marshal(snapshot)
	if err := os.WriteFile(filepath.Join(root, "snapshot.json"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := adapter.Rollback(context.Background(), networkExecutionPlan(), root); err != nil {
		t.Fatal(err)
	}
	current, err := os.ReadFile(global)
	if err != nil || string(current) != "new external config" {
		t.Fatalf("node rollback rewrote an unowned global config: %q err=%v", current, err)
	}
}
