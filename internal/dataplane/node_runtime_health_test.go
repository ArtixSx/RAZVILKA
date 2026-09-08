package dataplane

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/engineconfig"
)

func committedNodeHealthFixture(t *testing.T) (*Manager, Plan) {
	t.Helper()
	m := New(t.TempDir())
	m.FreshProfile = func(context.Context) (string, error) { return executionNetwork, nil }
	p := networkExecutionPlan()
	p.State, p.PlanID = "committed", "dp-0123456789abcdef"
	if err := m.Record(p); err != nil {
		t.Fatal(err)
	}
	return m, p
}

func TestCommittedNodeHealthRejectsDeadOwnedProcessesWithoutStartingOrRewriting(t *testing.T) {
	for _, running := range []string{"none", "engine-only", "sidecar-only"} {
		t.Run(running, func(t *testing.T) {
			m, p := committedNodeHealthFixture(t)
			a, err := NewProxyTunnelAdapter("sing-box", engineconfig.New(t.TempDir(), t.TempDir()), t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			processes := &proxyFakeProcesses{running: map[string]bool{}}
			if running == "engine-only" {
				processes.running[a.engineProcess().ID] = true
			} else if running == "sidecar-only" {
				processes.running[a.sidecarProcess().ID] = true
			}
			a.Processes, a.FreshProfile = processes, m.FreshProfile
			if err := m.Register(a); err != nil {
				t.Fatal(err)
			}
			root := filepath.Join(m.StateRoot, "transactions", p.PlanID, "sing-box")
			if err := os.MkdirAll(root, 0700); err != nil {
				t.Fatal(err)
			}
			state := PolicyState{Interface: a.Interface, Table: a.Table, PriorityBase: a.Priority, Prefixes: []string{"8.8.8.8/32"}}
			data, _ := json.Marshal(state)
			for _, path := range []string{filepath.Join(root, "policy.staged.json"), a.policyPath(), a.engineConfigPath(), a.sidecarConfigPath()} {
				if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, data, 0600); err != nil {
					t.Fatal(err)
				}
			}
			before, _ := os.ReadFile(filepath.Join(m.StateRoot, "latest-committed-plan.json"))
			if err := m.CheckCommittedNodeHealth(context.Background(), p); err == nil || err.Error() != "managed proxy or TUN sidecar is not running" {
				t.Fatalf("dead runtime accepted or wrong check: %v", err)
			}
			after, _ := os.ReadFile(filepath.Join(m.StateRoot, "latest-committed-plan.json"))
			wantRunning := 1
			if running == "none" {
				wantRunning = 0
			}
			if string(before) != string(after) || len(processes.startSpecs) != 0 || len(processes.running) != wantRunning {
				t.Fatal("read-only health changed processes or committed intent")
			}
		})
	}
}

func TestCommittedNodeHealthUsesRefreshedLivePolicyInsteadOfStagedSnapshot(t *testing.T) {
	m, plan := committedNodeHealthFixture(t)
	configRoot := t.TempDir()
	configs := engineconfig.New(filepath.Join(configRoot, "stage"), filepath.Join(configRoot, "backups"))
	a, err := NewProxyTunnelAdapter("sing-box", configs, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	processes := &proxyFakeProcesses{running: map[string]bool{}}
	a.Processes = processes
	a.Runner = &proxyFakeRunner{processes: processes, iface: a.Interface}
	a.EngineBin, a.SidecarBin, a.IP = "sing-box", "sing-box", "ip"
	a.IPTables, a.IP6Tables = "iptables", "ip6tables"
	a.FreshProfile = m.FreshProfile
	a.SOCKSProbe = func(context.Context, string) error { return nil }
	a.Probe = func(context.Context, string) error { return nil }
	a.ServiceIPProbe = func(context.Context, string, string, netip.Addr) error { return nil }
	a.NodeRoutes = func(context.Context, []NodeRouteRequest, string, time.Time) (NodeRouteMaterial, error) {
		return NodeRouteMaterial{Config: []byte(`{"outbounds":[{"type":"vless","server":"node.example","server_port":443}]}`), EndpointHosts: []string{"node.example"}}, nil
	}
	destination := "8.8.8.8"
	a.Resolver = func(ctx context.Context, host string) ([]netip.Addr, error) {
		if host == "node.example" {
			return []netip.Addr{netip.MustParseAddr("1.1.1.1")}, nil
		}
		return []netip.Addr{netip.MustParseAddr(destination)}, nil
	}
	// Install exact-node material through ordinary adapter phases. No engine
	// draft is part of this transaction, so Commit cannot touch global config.
	setup := plan
	setup.Routes = append([]Route(nil), plan.Routes...)
	setup.Routes[0].Sources = []string{"192.168.1.25/32"}
	root := filepath.Join(m.StateRoot, "transactions", plan.PlanID, "sing-box")
	for _, step := range []func(context.Context, Plan, string) error{a.Snapshot, a.Stage, a.Activate, a.Health, a.Commit} {
		if err := step(context.Background(), setup, root); err != nil {
			t.Fatal(err)
		}
	}
	plan.Routes[0].Sources = setup.Routes[0].Sources
	if err := m.Record(plan); err != nil {
		t.Fatal(err)
	}
	if err := m.Register(a); err != nil {
		t.Fatal(err)
	}
	destination = "8.8.4.4"
	if changed, err := a.RefreshPolicy(context.Background(), plan); err != nil || !changed {
		t.Fatalf("fixture policy did not refresh: %v %v", changed, err)
	}
	if err := a.Health(context.Background(), plan, root); err == nil {
		t.Fatal("staged snapshot unexpectedly matches refreshed policy")
	}
	policyBefore, _ := os.ReadFile(a.policyPath())
	startsBefore := len(processes.startSpecs)
	if err := m.CheckCommittedNodeHealth(context.Background(), plan); err != nil {
		t.Fatalf("healthy refreshed runtime rejected: %v", err)
	}
	policyAfter, _ := os.ReadFile(a.policyPath())
	if string(policyBefore) != string(policyAfter) || startsBefore != len(processes.startSpecs) {
		t.Fatal("health check rewrote policy or restarted process")
	}
	for _, source := range []string{"", "192.168.1.0/24", "192.168.1.41/32"} {
		var altered PolicyState
		if err := json.Unmarshal(policyBefore, &altered); err != nil {
			t.Fatal(err)
		}
		for index := range altered.Rules {
			altered.Rules[index].Source = source
		}
		data, _ := json.Marshal(altered)
		if err := os.WriteFile(a.policyPath(), data, 0600); err != nil {
			t.Fatal(err)
		}
		if err := m.CheckCommittedNodeHealth(context.Background(), plan); err == nil || err.Error() != "committed node client scope differs from applied plan" {
			t.Fatalf("changed source scope accepted or not rejected before runtime evidence: source=%q err=%v", source, err)
		}
	}
}

func TestCommittedNodeHealthGuardsPlanNetworkAndReviewAcrossHealth(t *testing.T) {
	for _, change := range []string{"none", "plan", "network", "review-before", "review-during", "network-during", "canceled"} {
		t.Run(change, func(t *testing.T) {
			m, p := committedNodeHealthFixture(t)
			reviewOK := true
			a := &networkExecutionAdapter{fakeAdapter: &fakeAdapter{id: "sing-box"}, after: func(name string) error {
				if change == "review-during" {
					reviewOK = false
				} else if change == "network-during" {
					m.FreshProfile = func(context.Context) (string, error) { return "wan-ffffffffffff", nil }
				}
				return nil
			}}
			if err := m.Register(a); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			ctx = WithReviewGuard(ctx, func(context.Context) error {
				if !reviewOK {
					return ErrReviewChanged
				}
				return nil
			})
			switch change {
			case "plan":
				p.Routes[0].Sources = []string{"192.168.1.99/32"}
			case "network":
				m.FreshProfile = func(context.Context) (string, error) { return "wan-ffffffffffff", nil }
			case "review-before":
				reviewOK = false
			case "canceled":
				cancel()
			}
			err := m.CheckCommittedNodeHealth(ctx, p)
			if (change == "none") != (err == nil) {
				t.Fatalf("change=%s error=%v", change, err)
			}
			shouldCall := change == "none" || change == "review-during" || change == "network-during"
			if shouldCall && !reflect.DeepEqual(a.calls, []string{"health"}) || !shouldCall && len(a.calls) != 0 {
				t.Fatalf("mutation or stale preflight: %v", a.calls)
			}
			if change == "canceled" && !errors.Is(err, context.Canceled) {
				t.Fatal(err)
			}
		})
	}
}
