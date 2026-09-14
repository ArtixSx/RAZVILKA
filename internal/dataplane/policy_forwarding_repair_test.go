package dataplane

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/engineconfig"
)

type forwardingRepairFixture struct {
	m         *Manager
	a         *ProxyTunnelAdapter
	firewall  *proxyFirewallFake
	processes *proxyFakeProcesses
	state     PolicyState
	plan      Plan
	profile   string
	files     map[string][]byte
}

func newForwardingRepairFixture(t *testing.T) *forwardingRepairFixture {
	t.Helper()
	a, runner, state := proxyForwardingFixture(t)
	state.RuleLayout, state.SharedPriorityBase = 2, 64
	ctx := context.Background()
	if err := a.installForwarding(ctx, state); err != nil {
		t.Fatal(err)
	}
	if err := applyPolicy(ctx, runner, "ip", state); err != nil {
		t.Fatal(err)
	}
	f := &forwardingRepairFixture{m: New(t.TempDir()), a: a, firewall: runner.firewall, processes: runner.processes, state: state, profile: executionNetwork}
	f.finish(t, []string{state.Rules[0].Source})
	return f
}

func (f *forwardingRepairFixture) finish(t *testing.T, sources []string) {
	t.Helper()
	f.m.FreshProfile = func(context.Context) (string, error) { return f.profile, nil }
	f.a.FreshProfile = f.m.FreshProfile
	f.a.Processes = f.processes
	f.a.EngineBin, f.a.SidecarBin = "sing-box", "sing-box"
	f.processes.running[f.a.engineProcess().ID] = true
	f.processes.running[f.a.sidecarProcess().ID] = true
	if err := os.MkdirAll(f.a.runtimeRoot(), 0700); err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(f.state)
	for path, data := range map[string][]byte{f.a.policyPath(): data, f.a.engineConfigPath(): []byte(`{}`), f.a.sidecarConfigPath(): []byte(`{}`)} {
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	f.plan = networkExecutionPlan()
	f.plan.State, f.plan.PlanID = "committed", "dp-0123456789abcdef"
	f.plan.Routes[0].Sources = sources
	if err := f.m.Record(f.plan); err != nil {
		t.Fatal(err)
	}
	if err := f.m.Register(f.a); err != nil {
		t.Fatal(err)
	}
	f.files = map[string][]byte{}
	for _, path := range []string{f.a.policyPath(), f.a.forwardingPath(), f.a.engineConfigPath(), f.a.sidecarConfigPath()} {
		f.files[path], _ = os.ReadFile(path)
	}
	f.firewall.calls = nil
}

func eraseForwardingTable(firewall *proxyFirewallFake, binary, name, chain string) {
	table := firewall.table(binary, name)
	delete(table, chain)
	for parent, rules := range table {
		var retained [][]string
		for _, rule := range rules {
			if len(rule) > 1 && rule[len(rule)-1] == chain {
				continue
			}
			retained = append(retained, rule)
		}
		table[parent] = retained
	}
}

func firewallImage(t *testing.T, table map[string][][]string) []byte {
	t.Helper()
	data, err := json.Marshal(table)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func (f *forwardingRepairFixture) unchangedPrivateRuntime(t *testing.T) {
	t.Helper()
	for path, before := range f.files {
		after, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(before, after) {
			t.Fatal("restoration changed runtime configuration or the original ownership lease")
		}
	}
	if len(f.processes.startSpecs) != 0 || !f.processes.running[f.a.engineProcess().ID] || !f.processes.running[f.a.sidecarProcess().ID] {
		t.Fatal("restoration restarted or stopped a process")
	}
	actual, exists, err := f.m.Committed()
	if err != nil || !exists || !reflect.DeepEqual(actual, f.plan) {
		t.Fatal("restoration changed the committed plan")
	}
}

func requireOnlyFirewallReads(t *testing.T, firewall *proxyFirewallFake) {
	t.Helper()
	for _, call := range firewall.calls {
		if !strings.HasSuffix(call, " -S") {
			t.Fatal("refused restoration mutated firewall")
		}
	}
}

func TestRestoreCommittedForwardingWholeFilterLossPreservesNATAndProcesses(t *testing.T) {
	f := newForwardingRepairFixture(t)
	nat := firewallImage(t, f.firewall.table("iptables", "nat"))
	eraseForwardingTable(f.firewall, "iptables", "filter", f.state.Forwarding.Chain)
	if err := f.a.observeOwnedRuntime(context.Background()); err == nil {
		t.Fatal("missing filter was falsely live")
	}
	restored, err := f.m.RestoreCommittedForwarding(context.Background(), f.plan)
	if err != nil || !restored["sing-box"] || len(restored) != 1 {
		t.Fatalf("whole missing filter did not recover: %v", err)
	}
	if !bytes.Equal(nat, firewallImage(t, f.firewall.table("iptables", "nat"))) {
		t.Fatal("intact NAT table was changed")
	}
	for _, call := range f.firewall.calls {
		if strings.Contains(call, "-t nat") && !strings.HasSuffix(call, " -S") {
			t.Fatal("restoration mutated intact NAT")
		}
	}
	if err := f.a.observeOwnedRuntime(context.Background()); err != nil {
		t.Fatal(err)
	}
	f.unchangedPrivateRuntime(t)
	f.firewall.calls = nil
	if restored, err := f.m.RestoreCommittedForwarding(context.Background(), f.plan); err != nil || len(restored) != 0 {
		t.Fatalf("healthy no-op was not idempotent: %v", err)
	}
	requireOnlyFirewallReads(t, f.firewall)
}

func TestRestoreCommittedForwardingRefusesPartialForeignAndIntactSiblingDrift(t *testing.T) {
	for _, damage := range []string{"missing-one-rule", "empty-owned-chain", "missing-one-jump", "foreign-owned-rule", "foreign-reference", "intact-nat-missing-jump", "intact-nat-foreign-rule", "later-acl"} {
		t.Run(damage, func(t *testing.T) {
			f := newForwardingRepairFixture(t)
			filter, nat := f.firewall.table("iptables", "filter"), f.firewall.table("iptables", "nat")
			chain := f.state.Forwarding.Chain
			switch damage {
			case "missing-one-rule":
				filter[chain] = filter[chain][1:]
			case "empty-owned-chain":
				filter[chain] = nil
			case "missing-one-jump":
				filter["FORWARD"] = filter["FORWARD"][:len(filter["FORWARD"])-1]
			case "foreign-owned-rule":
				filter[chain] = append(filter[chain], []string{"-j", "DROP"})
			case "foreign-reference":
				filter["NDM"] = append(filter["NDM"], []string{"-j", chain})
			case "intact-nat-missing-jump":
				eraseForwardingTable(f.firewall, "iptables", "filter", chain)
				nat["POSTROUTING"] = nat["POSTROUTING"][1:]
			case "intact-nat-foreign-rule":
				eraseForwardingTable(f.firewall, "iptables", "filter", chain)
				nat[chain] = append(nat[chain], []string{"-j", "DROP"})
			case "later-acl":
				filter["FORWARD"] = append(filter["FORWARD"], []string{"-j", "DROP"})
			}
			beforeFilter, beforeNAT := firewallImage(t, filter), firewallImage(t, nat)
			if restored, err := f.m.RestoreCommittedForwarding(context.Background(), f.plan); err == nil || len(restored) != 0 {
				t.Fatal("changed/partial/foreign ownership was silently repaired")
			}
			requireOnlyFirewallReads(t, f.firewall)
			if !bytes.Equal(beforeFilter, firewallImage(t, filter)) || !bytes.Equal(beforeNAT, firewallImage(t, nat)) {
				t.Fatal("refusal changed existing firewall state")
			}
		})
	}
}

func TestRestoreCommittedForwardingAuthorityGuardsRefuseBeforeWrites(t *testing.T) {
	for _, reason := range []string{"new-wan", "dead-engine", "dead-sidecar", "changed-plan", "changed-lease", "unacknowledged-table", "scope-mismatch", "caller-review", "cancelled"} {
		t.Run(reason, func(t *testing.T) {
			f := newForwardingRepairFixture(t)
			eraseForwardingTable(f.firewall, "iptables", "filter", f.state.Forwarding.Chain)
			ctx := context.Background()
			switch reason {
			case "new-wan":
				f.profile = "wan-ffffffffffff"
			case "dead-engine":
				f.processes.running[f.a.engineProcess().ID] = false
			case "dead-sidecar":
				f.processes.running[f.a.sidecarProcess().ID] = false
			case "changed-plan":
				f.plan.Revision++
			case "changed-lease":
				lease, _, _ := f.a.readForwardingLease()
				lease.Policy.Exclusions = []string{"198.51.100.1/32"}
				if err := f.a.writeForwardingLease(lease); err != nil {
					t.Fatal(err)
				}
			case "unacknowledged-table":
				lease, _, _ := f.a.readForwardingLease()
				lease.Created = []string{"false/nat"}
				if err := f.a.writeForwardingLease(lease); err != nil {
					t.Fatal(err)
				}
			case "scope-mismatch":
				f.plan.Routes[0].Sources = []string{"192.168.1.41/32"}
				if err := f.m.Record(f.plan); err != nil {
					t.Fatal(err)
				}
			case "caller-review":
				ctx = WithReviewGuard(ctx, func(context.Context) error { return ErrReviewChanged })
			case "cancelled":
				cancelled, cancel := context.WithCancel(ctx)
				cancel()
				ctx = cancelled
			}
			if restored, err := f.m.RestoreCommittedForwarding(ctx, f.plan); err == nil || len(restored) != 0 {
				t.Fatal("invalid restoration authority succeeded")
			}
			requireOnlyFirewallReads(t, f.firewall)
		})
	}
}

func TestRestoreCommittedForwardingFailureRollsBackOnlyNewTable(t *testing.T) {
	for _, phase := range []string{"create", "child", "attachment", "cancel-after-create", "wan-after-create", "foreign-during-create", "parent-during-build"} {
		t.Run(phase, func(t *testing.T) {
			f := newForwardingRepairFixture(t)
			chain := f.state.Forwarding.Chain
			eraseForwardingTable(f.firewall, "iptables", "filter", chain)
			nat := firewallImage(t, f.firewall.table("iptables", "nat"))
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			injected := false
			f.firewall.fail = func(call string) bool {
				if injected {
					return false
				}
				creation := strings.Contains(call, " -N "+chain)
				child := strings.Contains(call, " -A "+chain)
				attachment := strings.Contains(call, " -A FORWARD")
				switch {
				case phase == "create" && creation, phase == "child" && child, phase == "attachment" && attachment:
					injected = true
					return true
				case phase == "cancel-after-create" && creation:
					injected = true
					cancel()
				case phase == "wan-after-create" && creation:
					injected = true
					f.profile = "wan-ffffffffffff"
				case phase == "foreign-during-create" && creation:
					injected = true
					f.firewall.table("iptables", "filter")[chain] = [][]string{{"-j", "DROP"}}
				case phase == "parent-during-build" && child:
					injected = true
					table := f.firewall.table("iptables", "filter")
					table["FORWARD"] = append(table["FORWARD"], []string{"-j", "DROP"})
				}
				return false
			}
			if restored, err := f.m.RestoreCommittedForwarding(ctx, f.plan); err == nil || len(restored) != 0 || !injected {
				t.Fatal("injected restoration failure was not refused")
			}
			if !bytes.Equal(nat, firewallImage(t, f.firewall.table("iptables", "nat"))) {
				t.Fatal("failure cleanup touched intact NAT")
			}
			filter := f.firewall.table("iptables", "filter")
			if phase == "foreign-during-create" {
				if !reflect.DeepEqual(filter[chain], [][]string{{"-j", "DROP"}}) {
					t.Fatal("foreign chain created during race was removed")
				}
			} else if _, remains := filter[chain]; remains {
				t.Fatal("failure left its newly created chain")
			}
			for _, call := range f.firewall.calls {
				if strings.Contains(call, " -F") || strings.Contains(call, "-t nat") && !strings.HasSuffix(call, " -S") {
					t.Fatal("restoration cleanup exceeded its exact new objects")
				}
			}
		})
	}
}

func TestRestoreCommittedForwardingCancellationWhileWaitingForOperationGate(t *testing.T) {
	f := newForwardingRepairFixture(t)
	if err := f.m.beginOperation(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer f.m.endOperation()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := f.m.RestoreCommittedForwarding(ctx, f.plan); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("waiting operation did not respect caller deadline: %v", err)
	}
	if len(f.firewall.calls) != 0 {
		t.Fatal("waiting operation inspected or mutated firewall without its lease")
	}
}

func TestRestoreCommittedForwardingAllLANUsesOnlyRecordedConnectedPrefixes(t *testing.T) {
	for _, v6 := range []bool{false, true} {
		name := "IPv4"
		if v6 {
			name = "IPv6"
		}
		t.Run(name, func(t *testing.T) {
			lan := newProxyLANFixture(t)
			a, firewall := lan.a, &proxyFirewallFake{}
			base := a.Runner
			a.Runner = networkCleanupRunner(func(ctx context.Context, name string, args ...string) ([]byte, error) {
				if name == "iptables" || name == "ip6tables" {
					return firewall.Run(ctx, name, args...)
				}
				return base.Run(ctx, name, args...)
			})
			state := lan.policy(v6, "")
			state.RuleLayout, state.SharedPriorityBase = 2, 64
			if err := a.prepareForwarding(context.Background(), &state); err != nil {
				t.Fatal(err)
			}
			if err := a.installForwarding(context.Background(), state); err != nil {
				t.Fatal(err)
			}
			if err := applyPolicy(context.Background(), a.Runner, "ip", state); err != nil {
				t.Fatal(err)
			}
			f := &forwardingRepairFixture{m: New(t.TempDir()), a: a, firewall: firewall, processes: &proxyFakeProcesses{running: map[string]bool{}}, state: state, profile: executionNetwork}
			f.finish(t, nil)
			if !v6 {
				// Global and explicit routes can canonically share one LAN rule.
				f.plan.Routes = append(f.plan.Routes, Route{ServiceID: "scoped-fixture", Resolved: "sing-box", Sources: []string{"192.168.1.25/32"}, CIDRs: []string{"198.51.100.20/32"}})
				if err := f.m.Record(f.plan); err != nil {
					t.Fatal(err)
				}
				// A new connected LAN is not new authority for this repair.
				lan.main4 += "192.168.50.0/24 dev br2 scope link src 192.168.50.1\n"
				lan.addresses["br2"] = "37: br2: <UP> mtu1500\n inet 192.168.50.1/24 scope global br2\n"
				lan.members["br2"] = []string{"fixture0"}
			}
			binary := "iptables"
			if v6 {
				binary = "ip6tables"
			}
			eraseForwardingTable(firewall, binary, "filter", state.Forwarding.Chain)
			if restored, err := f.m.RestoreCommittedForwarding(context.Background(), f.plan); err != nil || !restored["sing-box"] {
				t.Fatalf("recorded all-LAN grants failed to restore: %v", err)
			}
			for _, rule := range firewall.table(binary, "filter")[state.Forwarding.Chain] {
				if strings.Contains(strings.Join(rule, " "), "192.168.50.") {
					t.Fatal("repair acquired a new LAN scope")
				}
			}
			f.unchangedPrivateRuntime(t)
		})
	}
}

func TestRestoreCommittedForwardingMultipleAdaptersShareTableWithoutAdoptingForeignChanges(t *testing.T) {
	for _, failSecond := range []bool{false, true} {
		t.Run(map[bool]string{false: "both restore", true: "second fails and first rolls back"}[failSecond], func(t *testing.T) {
			f := newForwardingRepairFixture(t)
			second, err := NewProxyTunnelAdapter("xray", engineconfig.New(t.TempDir(), t.TempDir()), t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			base := f.a.Runner
			shared := networkCleanupRunner(func(ctx context.Context, name string, args ...string) ([]byte, error) {
				if name == "ip" && len(args) >= 3 && args[0] == "route" && args[1] == "get" && args[2] == "198.51.100.21" {
					return []byte("198.51.100.21 dev " + second.Interface), nil
				}
				return base.Run(ctx, name, args...)
			})
			f.a.Runner, second.Runner = shared, shared
			second.IP, second.IPTables, second.IP6Tables = "ip", "iptables", "ip6tables"
			second.Processes, second.FreshProfile = f.processes, f.m.FreshProfile
			second.EngineBin, second.SidecarBin = "xray", "sing-box"
			f.processes.running[second.engineProcess().ID], f.processes.running[second.sidecarProcess().ID] = true, true
			state := PolicyState{Interface: second.Interface, Table: second.Table, PriorityBase: second.Priority, RuleLayout: 2, SharedPriorityBase: 66, Prefixes: []string{"198.51.100.21/32"}, Rules: []PolicyRule{{Source: "192.168.1.25/32", Destination: "198.51.100.21/32"}}}
			state.Forwarding, err = second.compileForwarding(context.Background(), state)
			if err != nil {
				t.Fatal(err)
			}
			if err := second.installForwarding(context.Background(), state); err != nil {
				t.Fatal(err)
			}
			if err := applyPolicy(context.Background(), shared, "ip", state); err != nil {
				t.Fatal(err)
			}
			if err := os.MkdirAll(second.runtimeRoot(), 0700); err != nil {
				t.Fatal(err)
			}
			data, _ := json.Marshal(state)
			for path, data := range map[string][]byte{second.policyPath(): data, second.engineConfigPath(): []byte(`{}`), second.sidecarConfigPath(): []byte(`{}`)} {
				if err := os.WriteFile(path, data, 0600); err != nil {
					t.Fatal(err)
				}
			}
			if err := f.m.Register(second); err != nil {
				t.Fatal(err)
			}
			f.plan.Adapters = append(f.plan.Adapters, "xray")
			f.plan.Routes = append(f.plan.Routes, Route{ServiceID: "second-fixture", Resolved: "xray", Sources: []string{"192.168.1.25/32"}, CIDRs: state.Prefixes})
			if err := f.m.Record(f.plan); err != nil {
				t.Fatal(err)
			}
			eraseForwardingTable(f.firewall, "iptables", "filter", f.state.Forwarding.Chain)
			eraseForwardingTable(f.firewall, "iptables", "filter", state.Forwarding.Chain)
			nat := firewallImage(t, f.firewall.table("iptables", "nat"))
			f.firewall.calls = nil
			if failSecond {
				f.firewall.fail = func(call string) bool { return strings.Contains(call, " -N "+state.Forwarding.Chain) }
			}
			restored, err := f.m.RestoreCommittedForwarding(context.Background(), f.plan)
			if failSecond {
				if err == nil || len(restored) != 0 {
					t.Fatal("second adapter failure was ignored")
				}
				for _, chain := range []string{f.state.Forwarding.Chain, state.Forwarding.Chain} {
					if _, remains := f.firewall.table("iptables", "filter")[chain]; remains {
						t.Fatal("failed multi-adapter attempt left its new chain")
					}
				}
			} else if err != nil || len(restored) != 2 || !restored["sing-box"] || !restored["xray"] {
				t.Fatalf("own first repair was mistaken for foreign table drift: %v", err)
			}
			if !bytes.Equal(nat, firewallImage(t, f.firewall.table("iptables", "nat"))) {
				t.Fatal("multi-adapter repair changed intact NAT")
			}
			f.unchangedPrivateRuntime(t)
		})
	}
}
