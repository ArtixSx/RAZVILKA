package dataplane

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
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
	a.bootIdentity = func() (string, error) { return "node-health-test-boot", nil }
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
	setup.Routes[0].Domains = nil
	setup.Routes[0].CIDRs = []string{"8.8.8.8/32"}
	setup.Routes[0].Sources = []string{"192.168.1.25/32"}
	root := filepath.Join(m.StateRoot, "transactions", plan.PlanID, "sing-box")
	for _, step := range []func(context.Context, Plan, string) error{a.Snapshot, a.Stage, a.Activate, a.Health, a.Commit} {
		if err := step(context.Background(), setup, root); err != nil {
			t.Fatal(err)
		}
	}
	plan.Routes[0] = setup.Routes[0]
	if err := m.Record(plan); err != nil {
		t.Fatal(err)
	}
	if err := m.Register(a); err != nil {
		t.Fatal(err)
	}
	// Model an explicitly reviewed CIDR update. DNS-derived expansion is
	// refused by the legacy adapter and cannot grant this change.
	destination = "8.8.4.4"
	plan.Routes[0].CIDRs = []string{"8.8.4.4/32"}
	if err := m.Record(plan); err != nil {
		t.Fatal(err)
	}
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

func TestCommittedNodeHealthEngineSelection(t *testing.T) {
	first, second := "node-"+strings.Repeat("a", 64), "node-"+strings.Repeat("b", 64)
	group := "group-" + strings.Repeat("c", 32)
	node := func(engine string) Route {
		return Route{Selected: engine + ":" + first, Resolved: engine + ":" + first}
	}
	for _, test := range []struct {
		name string
		plan Plan
		want []string
	}{
		{"sing-box", Plan{Adapters: []string{"sing-box"}, Routes: []Route{node("sing-box")}}, []string{"sing-box"}},
		{"xray", Plan{Adapters: []string{"xray"}, Routes: []Route{node("xray")}}, []string{"xray"}},
		{"both-deduplicated", Plan{Adapters: []string{"xray", "sing-box"}, Routes: []Route{node("xray"), node("sing-box"), node("xray")}}, []string{"sing-box", "xray"}},
		{"selected-group", Plan{Adapters: []string{"xray"}, Routes: []Route{{Selected: "xray:" + group, Resolved: "xray:" + second}}}, []string{"xray"}},
		{"auto", Plan{Adapters: []string{"xray"}, Routes: []Route{{Selected: "auto", Resolved: "xray:" + first}}}, []string{"xray"}},
		{"non-node-cells", Plan{Adapters: []string{"nfqws2", "sing-box", "xray"}, Routes: []Route{node("xray"),
			{Selected: "default", Resolved: "direct"}, {Selected: "nfqws2", Resolved: "nfqws2"},
			{Selected: "sing-box:home", Resolved: "sing-box:home"}}}, []string{"xray"}},
		{"no-node", Plan{Adapters: []string{"xray"}, Routes: []Route{{Selected: "xray:home", Resolved: "xray:home"}}}, nil},
		{"missing-adapter", Plan{Routes: []Route{node("xray")}}, nil},
		{"wrong-adapter", Plan{Adapters: []string{"sing-box"}, Routes: []Route{node("xray")}}, nil},
		{"unrouted-adapter", Plan{Adapters: []string{"sing-box", "xray"}, Routes: []Route{node("sing-box")}}, nil},
		{"duplicate-adapter", Plan{Adapters: []string{"xray", "xray"}, Routes: []Route{node("xray")}}, nil},
		{"changed-engine", Plan{Adapters: []string{"sing-box", "xray"}, Routes: []Route{{Selected: "sing-box:" + first, Resolved: "xray:" + first}}}, nil},
		{"changed-exact-node", Plan{Adapters: []string{"xray"}, Routes: []Route{{Selected: "xray:" + first, Resolved: "xray:" + second}}}, nil},
		{"unresolved-group", Plan{Adapters: []string{"xray"}, Routes: []Route{{Selected: "xray:" + group, Resolved: "xray:" + group}}}, nil},
		{"node-became-profile", Plan{Adapters: []string{"xray"}, Routes: []Route{{Selected: "xray:" + first, Resolved: "xray:home"}}}, nil},
		{"unknown-node-engine", Plan{Adapters: []string{"xray"}, Routes: []Route{{Selected: "unknown:" + first, Resolved: "xray:" + first}}}, nil},
		{"unknown-group-engine", Plan{Adapters: []string{"xray"}, Routes: []Route{{Selected: "unknown:" + group, Resolved: "xray:" + first}}}, nil},
		{"malformed-selected", Plan{Adapters: []string{"xray"}, Routes: []Route{{Selected: "xray:node-short", Resolved: "xray:" + first}}}, nil},
		{"malformed-resolved", Plan{Adapters: []string{"xray"}, Routes: []Route{{Selected: "auto", Resolved: "xray:node-short"}}}, nil},
		{"missing-node-engine", Plan{Adapters: []string{"xray"}, Routes: []Route{{Selected: first, Resolved: "xray:" + first}}}, nil},
		{"case", Plan{Adapters: []string{"xray"}, Routes: []Route{{Selected: "Xray:" + first, Resolved: "xray:" + first}}}, nil},
		{"whitespace", Plan{Adapters: []string{"xray"}, Routes: []Route{{Selected: "xray:" + first, Resolved: " xray:" + first}}}, nil},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := committedNodeHealthEngines(test.plan)
			if test.want == nil {
				if !errors.Is(err, ErrReviewChanged) || len(got) != 0 {
					t.Fatalf("invalid node references accepted: %v %v", got, err)
				}
			} else if err != nil || !reflect.DeepEqual(got, test.want) {
				t.Fatalf("engines=%v err=%v want=%v", got, err, test.want)
			}
		})
	}
}

func committedXrayHealthPlan(t *testing.T, mixed bool) (*Manager, Plan) {
	t.Helper()
	m, plan := committedNodeHealthFixture(t)
	if mixed {
		plan.Routes = append(plan.Routes, plan.Routes[0])
		plan.Routes[1].ServiceID = "xray-service"
		plan.Adapters = []string{"nfqws2", "xray", "sing-box"}
		plan.Routes = append(plan.Routes, Route{ServiceID: "other", Selected: "nfqws2", Resolved: "nfqws2"})
	} else {
		plan.Adapters = []string{"xray"}
	}
	index := 0
	if mixed {
		index = 1
	}
	plan.Routes[index].Selected = "xray:" + checkedNodeID
	plan.Routes[index].Resolved = plan.Routes[index].Selected
	if err := m.Record(plan); err != nil {
		t.Fatal(err)
	}
	return m, plan
}

func TestCommittedNodeHealthRejectsInvalidReferencesBeforeConsumer(t *testing.T) {
	for _, ref := range []string{"sing-box:node-short", "unknown:" + checkedNodeID, "sing-box:group-short"} {
		t.Run(ref, func(t *testing.T) {
			m, plan := committedNodeHealthFixture(t)
			plan.Routes[0].Selected = ref
			if err := m.Record(plan); err != nil {
				t.Fatal(err)
			}
			adapter := &fakeAdapter{id: "sing-box"}
			if err := m.Register(adapter); err != nil {
				t.Fatal(err)
			}
			profiles := 0
			m.FreshProfile = func(context.Context) (string, error) {
				profiles++
				return executionNetwork, nil
			}
			if err := m.CheckCommittedNodeHealth(context.Background(), plan); !errors.Is(err, ErrReviewChanged) || len(adapter.calls) != 0 || profiles != 0 {
				t.Fatalf("invalid reference reached a consumer: %v calls=%v profiles=%d", err, adapter.calls, profiles)
			}
		})
	}
}

func committedXrayHealthAdapter(t *testing.T, m *Manager) *ProxyTunnelAdapter {
	t.Helper()
	a, err := NewScopedXrayRouterTunnelAdapter(engineconfig.New(t.TempDir(), t.TempDir()), t.TempDir(),
		func(context.Context, []NodeRouteRequest, string, time.Time) (NodeRouteMaterial, error) {
			panic("read-only committed health must not materialize or start a node")
		})
	if err != nil {
		t.Fatal(err)
	}
	a.FreshProfile = m.FreshProfile
	return a
}

type committedNodeHealthSpy struct{ *fakeAdapter }

func (a *committedNodeHealthSpy) CommittedNodeHealth(context.Context, Plan) error {
	return a.call("committed-node-health")
}

func TestCommittedNodeHealthXrayRequiresActualConfiguredVerifier(t *testing.T) {
	for _, mode := range []string{"missing", "generic-adapter", "foreign-committed-verifier", "generic-proxy", "no-materializer", "no-profile", "no-verifier", "configured-missing-runtime"} {
		t.Run(mode, func(t *testing.T) {
			m, plan := committedXrayHealthPlan(t, false)
			var generic *fakeAdapter
			if mode == "generic-adapter" || mode == "foreign-committed-verifier" {
				generic = &fakeAdapter{id: "xray"}
				var adapter Adapter = generic
				if mode == "foreign-committed-verifier" {
					adapter = &committedNodeHealthSpy{generic}
				}
				if err := m.Register(adapter); err != nil {
					t.Fatal(err)
				}
			} else if mode != "missing" {
				a := committedXrayHealthAdapter(t, m)
				switch mode {
				case "generic-proxy":
					a.scopedXray = false
				case "no-materializer":
					a.NodeRoutes = nil
				case "no-profile":
					a.FreshProfile = nil
				case "no-verifier":
					a.nodeRouterVerifier = false
				}
				if err := m.Register(a); err != nil {
					t.Fatal(err)
				}
			}
			before, err := os.ReadFile(filepath.Join(m.StateRoot, "latest-committed-plan.json"))
			if err != nil {
				t.Fatal(err)
			}
			err = m.CheckCommittedNodeHealth(context.Background(), plan)
			want := "committed Xray node runtime verifier is unavailable"
			if mode == "missing" {
				want = "committed node runtime adapter is unavailable"
			} else if mode == "configured-missing-runtime" && nodeRouterDeviceBindingAvailable() {
				want = "committed node runtime state is missing"
			}
			if err == nil || err.Error() != want {
				t.Fatalf("mode=%s got=%v want=%s", mode, err, want)
			}
			after, err := os.ReadFile(filepath.Join(m.StateRoot, "latest-committed-plan.json"))
			if err != nil || string(before) != string(after) || generic != nil && len(generic.calls) != 0 {
				t.Fatal("health adopted or rewrote intent, or used generic Xray Health")
			}
		})
	}
}

func TestCommittedNodeHealthMixedEnginesGuardsEachConsumer(t *testing.T) {
	for _, change := range []string{"none", "plan-before", "review-during", "network-during", "plan-during", "cancel-during"} {
		t.Run(change, func(t *testing.T) {
			m, plan := committedXrayHealthPlan(t, true)
			reviewOK := true
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			xray := committedXrayHealthAdapter(t, m)
			xrayChecks := 0
			xray.FreshProfile = func(context.Context) (string, error) {
				xrayChecks++
				return executionNetwork, nil
			}
			sing := &networkExecutionAdapter{fakeAdapter: &fakeAdapter{id: "sing-box"}, after: func(string) error {
				switch change {
				case "review-during":
					reviewOK = false
				case "network-during":
					m.FreshProfile = func(context.Context) (string, error) { return "wan-ffffffffffff", nil }
				case "plan-during":
					altered := plan
					altered.Revision++
					data, _ := json.Marshal(altered)
					return os.WriteFile(filepath.Join(m.StateRoot, "latest-committed-plan.json"), data, 0600)
				case "cancel-during":
					cancel()
				}
				return nil
			}}
			other := &fakeAdapter{id: "nfqws2", failAt: "health"}
			for _, adapter := range []Adapter{xray, sing, other} {
				if err := m.Register(adapter); err != nil {
					t.Fatal(err)
				}
			}
			ctx = WithReviewGuard(ctx, func(context.Context) error {
				if !reviewOK {
					return ErrReviewChanged
				}
				return nil
			})
			if change == "plan-before" {
				plan.Revision++
			}
			err := m.CheckCommittedNodeHealth(ctx, plan)
			if err == nil {
				t.Fatal("missing runtime or changed guard accepted")
			}
			if change == "none" {
				want := "committed Xray node runtime verifier is unavailable"
				if nodeRouterDeviceBindingAvailable() {
					want = "committed node runtime state is missing"
				}
				if err.Error() != want || (xrayChecks == 1) != nodeRouterDeviceBindingAvailable() {
					t.Fatalf("second exact node engine was not checked: %v checks=%d", err, xrayChecks)
				}
			} else {
				want := ErrReviewChanged
				if change == "network-during" {
					want = ErrNetworkChanged
				} else if change == "cancel-during" {
					want = context.Canceled
				}
				if !errors.Is(err, want) || xrayChecks != 0 {
					t.Fatalf("next engine ran after guard changed: %v checks=%d", err, xrayChecks)
				}
			}
			wantCalls := []string{"health"}
			if change == "plan-before" {
				wantCalls = nil
			}
			if !reflect.DeepEqual(sing.calls, wantCalls) || len(other.calls) != 0 {
				t.Fatalf("unscoped health or mutation: node=%v other=%v", sing.calls, other.calls)
			}
		})
	}
}
