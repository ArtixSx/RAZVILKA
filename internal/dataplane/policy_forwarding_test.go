package dataplane

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/ArtixSx/razvilka/internal/engineconfig"
)

// Stateful model: unknown deletion, duplicate chain creation and deleting a
// referenced/nonempty chain fail, just as the kernel does. This detects leaks
// and unsafe flushes rather than accepting every mocked command.
type proxyFirewallFake struct {
	tables map[string]map[string][][]string
	calls  []string
	fail   func(string) bool
}

func (r *proxyFirewallFake) table(name, table string) map[string][][]string {
	if r.tables == nil {
		r.tables = map[string]map[string][][]string{}
	}
	key := name + ":" + table
	if r.tables[key] == nil {
		parent := "FORWARD"
		if table == "nat" {
			parent = "POSTROUTING"
		}
		r.tables[key] = map[string][][]string{parent: {{"-j", "NDM"}}, "NDM": {{"-i", "wan0", "-j", "DROP"}}}
	}
	return r.tables[key]
}

func (r *proxyFirewallFake) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	command := name + " " + strings.Join(args, " ")
	r.calls = append(r.calls, command)
	if r.fail != nil && r.fail(command) {
		return nil, errors.New("injected firewall failure")
	}
	if len(args) < 3 || args[0] != "-t" {
		return nil, fmt.Errorf("unexpected firewall command %s", command)
	}
	chains := r.table(name, args[1])
	op := args[2]
	if op == "-S" {
		parent := "FORWARD"
		if args[1] == "nat" {
			parent = "POSTROUTING"
		}
		lines := []string{"-P " + parent + " DROP"}
		for chain, rules := range chains {
			if chain != parent {
				lines = append(lines, "-N "+chain)
			}
			for _, rule := range rules {
				lines = append(lines, "-A "+chain+" "+strings.Join(rule, " "))
			}
		}
		return []byte(strings.Join(lines, "\n") + "\n"), nil
	}
	if len(args) < 4 {
		return nil, errors.New("missing chain")
	}
	chain := args[3]
	rules, exists := chains[chain]
	switch op {
	case "-N":
		if exists {
			return nil, errors.New("chain exists")
		}
		chains[chain] = [][]string{}
	case "-A", "-I":
		if !exists {
			return nil, errors.New("chain missing")
		}
		position := len(rules)
		rule := args[4:]
		if op == "-I" {
			n, err := strconv.Atoi(args[4])
			if err != nil {
				return nil, err
			}
			position = n - 1
			rule = args[5:]
		}
		if position < 0 || position > len(rules) {
			return nil, errors.New("bad position")
		}
		updated := append([][]string{}, rules[:position]...)
		updated = append(updated, append([]string{}, rule...))
		updated = append(updated, rules[position:]...)
		chains[chain] = updated
	case "-D":
		found := -1
		for i, rule := range rules {
			if proxyFirewallRuleKey(rule) == proxyFirewallRuleKey(args[4:]) {
				found = i
				break
			}
		}
		if found < 0 {
			return nil, errors.New("rule missing")
		}
		chains[chain] = append(rules[:found], rules[found+1:]...)
	case "-X":
		if !exists || len(rules) > 0 {
			return nil, errors.New("chain missing or nonempty")
		}
		for _, rules := range chains {
			for _, rule := range rules {
				for i := 0; i+1 < len(rule); i++ {
					if rule[i] == "-j" && rule[i+1] == chain {
						return nil, errors.New("chain referenced")
					}
				}
			}
		}
		delete(chains, chain)
	default:
		return nil, fmt.Errorf("unsafe or unexpected operation %s", op)
	}
	return nil, nil
}

func proxyForwardingFixture(t *testing.T) (*ProxyTunnelAdapter, *proxyFakeRunner, PolicyState) {
	t.Helper()
	configRoot := t.TempDir()
	a, err := NewProxyTunnelAdapter("sing-box", engineconfig.New(filepath.Join(configRoot, "stage"), filepath.Join(configRoot, "backups")), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	r := &proxyFakeRunner{processes: &proxyFakeProcesses{running: map[string]bool{}}, iface: a.Interface}
	a.Runner = r
	a.IP = "ip"
	a.IPTables = "iptables"
	a.IP6Tables = "ip6tables"
	state := PolicyState{Interface: a.Interface, Table: a.Table, PriorityBase: a.Priority, Prefixes: []string{"198.51.100.20/32"}, Rules: []PolicyRule{{Source: "192.168.1.25/32", Destination: "198.51.100.20/32"}}}
	state.Forwarding, err = a.compileForwarding(context.Background(), state)
	if err != nil {
		t.Fatal(err)
	}
	return a, r, state
}

func TestProxyForwardingPreservesACLAndSourceThenRemovesOnlyOwnRules(t *testing.T) {
	a, r, state := proxyForwardingFixture(t)
	ctx := context.Background()
	if err := a.preflightForwarding(ctx, state); err != nil {
		t.Fatal(err)
	}
	for _, call := range r.firewall.calls {
		if !strings.HasSuffix(call, " -S") {
			t.Fatalf("preflight mutated firewall: %s", call)
		}
	}
	if err := a.installForwarding(ctx, state); err != nil {
		t.Fatal(err)
	}
	filter := r.firewall.table("iptables", "filter")
	if !reflect.DeepEqual(filter["FORWARD"][0], []string{"-j", "NDM"}) {
		t.Fatal("existing ACL was bypassed")
	}
	for _, rule := range filter[state.Forwarding.Chain] {
		joined := strings.Join(rule, " ")
		if !strings.Contains(joined, "192.168.1.25/32") || !strings.Contains(joined, "198.51.100.20/32") || !strings.Contains(joined, "br0") || !strings.Contains(joined, "rz-sing") {
			t.Fatalf("unscoped forwarding grant: %s", joined)
		}
		if strings.Contains(joined, "-i rz-sing") && !strings.Contains(joined, "--ctstate RELATED,ESTABLISHED") {
			t.Fatal("unrestricted inbound forwarding")
		}
	}
	nat := r.firewall.table("iptables", "nat")
	if got := strings.Join(nat["POSTROUTING"][0], " "); !strings.Contains(got, "-o rz-sing -s 192.168.1.25/32 -d 198.51.100.20/32") {
		t.Fatalf("source preservation is not exact: %s", got)
	}
	if err := a.verifyForwarding(ctx, state); err != nil {
		t.Fatal(err)
	}
	if err := a.removeForwarding(ctx); err != nil {
		t.Fatal(err)
	}
	for _, table := range []map[string][][]string{filter, nat} {
		if len(table) != 2 {
			t.Fatalf("owned chains leaked: %v", table)
		}
	}
	if _, err := os.Stat(a.forwardingPath()); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("manifest remained: %v", err)
	}
	if err := a.removeForwarding(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestProxyForwardingRejectsUnknownIngressAndFamily(t *testing.T) {
	for _, source := range []string{"", "192.168.1.0/24", "0.0.0.0/0", "127.0.0.1/32", "::ffff:192.168.1.25/128", "fd00::2/128"} {
		t.Run(source, func(t *testing.T) {
			a, _, state := proxyForwardingFixture(t)
			state.Rules[0].Source = source
			if _, err := a.compileForwarding(context.Background(), state); err == nil {
				t.Fatal("unsupported source received forwarding authority")
			}
		})
	}
}

func TestProxyForwardingIPv6UsesSeparateFilterAndNAT(t *testing.T) {
	a, r, state := proxyForwardingFixture(t)
	base := a.Runner
	a.Runner = networkCleanupRunner(func(ctx context.Context, name string, args ...string) ([]byte, error) {
		if name == "ip" {
			joined := strings.Join(args, " ")
			if joined == "-6 route get fd00::25" {
				return []byte("fd00::25 dev br0 src fd00::1"), nil
			}
			if joined == "-6 route show table main match fd00::25/128" {
				return []byte("fd00::/64 dev br0 proto kernel metric 256"), nil
			}
		}
		return base.Run(ctx, name, args...)
	})
	state.Prefixes = []string{"2001:db8::20/128"}
	state.Rules = []PolicyRule{{Source: "fd00::25/128", Destination: state.Prefixes[0]}}
	var err error
	state.Forwarding, err = a.compileForwarding(context.Background(), state)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.installForwarding(context.Background(), state); err != nil {
		t.Fatal(err)
	}
	for _, call := range r.firewall.calls {
		if strings.HasPrefix(call, "iptables ") {
			t.Fatalf("IPv6 grant touched IPv4: %s", call)
		}
	}
	if err := a.removeForwarding(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestProxyForwardingPartialInstallRollsBackAndRestartCleansManifest(t *testing.T) {
	for _, failure := range []string{"-A ", "-A FORWARD", "-I POSTROUTING"} {
		t.Run(failure, func(t *testing.T) {
			a, r, state := proxyForwardingFixture(t)
			r.firewall = &proxyFirewallFake{}
			failed := false
			r.firewall.fail = func(call string) bool {
				if !failed && strings.Contains(call, failure) {
					failed = true
					return true
				}
				return false
			}
			if err := a.installForwarding(context.Background(), state); err == nil {
				t.Fatal("partial install reported success")
			}
			for _, table := range r.firewall.tables {
				if len(table) != 2 {
					t.Fatalf("partial owned chain leaked: %v", table)
				}
			}
			if regularFile(a.forwardingPath()) {
				t.Fatal("failed installation retained manifest after successful cleanup")
			}
			if err := a.installForwarding(context.Background(), state); err != nil {
				t.Fatal(err)
			}
			// The independent adapter instance has no in-memory installation state.
			restarted := *a
			if err := restarted.removeForwarding(context.Background()); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestProxyForwardingForeignCollisionAndDriftFailClosed(t *testing.T) {
	t.Run("no-manifest", func(t *testing.T) {
		a, r, state := proxyForwardingFixture(t)
		r.firewall = &proxyFirewallFake{}
		r.firewall.table("iptables", "filter")[state.Forwarding.Chain] = [][]string{{"-j", "DROP"}}
		if err := a.installForwarding(context.Background(), state); err == nil {
			t.Fatal("foreign chain claimed")
		}
		if len(r.firewall.calls) != 1 || !strings.HasSuffix(r.firewall.calls[0], " -S") {
			t.Fatalf("collision mutated firewall: %v", r.firewall.calls)
		}
	})
	t.Run("foreign-rules-preserved", func(t *testing.T) {
		a, r, state := proxyForwardingFixture(t)
		if err := a.installForwarding(context.Background(), state); err != nil {
			t.Fatal(err)
		}
		table := r.firewall.table("iptables", "filter")
		table[state.Forwarding.Chain] = append(table[state.Forwarding.Chain], []string{"-j", "DROP"})
		if err := a.verifyForwarding(context.Background(), state); err == nil {
			t.Fatal("foreign drift accepted")
		}
		if err := a.removeForwarding(context.Background()); err == nil {
			t.Fatal("foreign chain deletion reported success")
		}
		if !reflect.DeepEqual(table[state.Forwarding.Chain], [][]string{{"-j", "DROP"}}) {
			t.Fatal("foreign chain contents were flushed")
		}
		if !regularFile(a.forwardingPath()) {
			t.Fatal("unresolved ownership evidence was discarded")
		}
	})
	t.Run("new-acl-after-jump", func(t *testing.T) {
		a, r, state := proxyForwardingFixture(t)
		if err := a.installForwarding(context.Background(), state); err != nil {
			t.Fatal(err)
		}
		table := r.firewall.table("iptables", "filter")
		table["FORWARD"] = append(table["FORWARD"], []string{"-s", "192.168.1.25/32", "-j", "DROP"})
		if err := a.verifyForwarding(context.Background(), state); err == nil {
			t.Fatal("new ACL priority silently bypassed")
		}
		if err := a.removeForwarding(context.Background()); err != nil {
			t.Fatal(err)
		}
		if len(table["FORWARD"]) != 2 {
			t.Fatal("foreign ACL removed")
		}
	})
}

func TestProxyForwardingChangedIngressCannotActivate(t *testing.T) {
	a, _, state := proxyForwardingFixture(t)
	a.Runner = networkCleanupRunner(func(context.Context, string, ...string) ([]byte, error) {
		return []byte("192.168.1.25 via 192.168.2.1 dev wan0"), nil
	})
	if err := a.installForwarding(context.Background(), state); err == nil {
		t.Fatal("changed source ingress retained authority")
	}
	if regularFile(a.forwardingPath()) {
		t.Fatal("failed preflight wrote ownership")
	}
}

func TestProxyForwardingRuleBounds(t *testing.T) {
	a, _, state := proxyForwardingFixture(t)
	for len(state.Rules) <= maxProxyForwardingRules {
		state.Rules = append(state.Rules, PolicyRule{Source: "192.168.1.25/32", Destination: netip.PrefixFrom(netip.AddrFrom4([4]byte{198, 51, 100, byte(len(state.Rules))}), 32).String()})
	}
	if _, err := a.compileForwarding(context.Background(), state); err == nil {
		t.Fatal("unbounded rule fanout accepted")
	}
}

func TestProxyForwardingCreationRaceNeverDeletesUnacknowledgedChain(t *testing.T) {
	a, r, state := proxyForwardingFixture(t)
	r.firewall = &proxyFirewallFake{}
	r.firewall.fail = func(call string) bool {
		if strings.Contains(call, "-t filter -N ") {
			// Another owner wins after read-only preflight, before our -N.
			r.firewall.table("iptables", "filter")[state.Forwarding.Chain] = [][]string{{"-j", "DROP"}}
			return true
		}
		return false
	}
	if err := a.installForwarding(context.Background(), state); err == nil {
		t.Fatal("ambiguous create succeeded")
	}
	if !regularFile(a.forwardingPath()) {
		t.Fatal("ambiguous creation evidence discarded")
	}
	for _, call := range r.firewall.calls {
		if strings.Contains(call, " -D ") || strings.Contains(call, " -X ") {
			t.Fatalf("unacknowledged chain was mutated: %s", call)
		}
	}
	if err := a.removeForwarding(context.Background()); err == nil {
		t.Fatal("restart claimed unacknowledged creation")
	}
}

func TestProxyForwardingIndependentTunnelsCoexistWithoutTrustingNames(t *testing.T) {
	a, r, state := proxyForwardingFixture(t)
	ctx := context.Background()
	if err := a.installForwarding(ctx, state); err != nil {
		t.Fatal(err)
	}
	filter := r.firewall.table("iptables", "filter")
	filter["FORWARD"] = append(filter["FORWARD"], []string{"-i", "br0", "-o", "unrelated-tun", "-j", "FOREIGN"})
	nat := r.firewall.table("iptables", "nat")
	nat["POSTROUTING"] = append([][]string{{"-o", "unrelated-tun", "-j", "FOREIGN"}}, nat["POSTROUTING"]...)
	if err := a.verifyForwarding(ctx, state); err != nil {
		t.Fatalf("disjoint unrelated rule invalidated this grant: %v", err)
	}
	filter["FORWARD"] = append(filter["FORWARD"], []string{"-i", "br+", "-o", "rz-sing", "-j", "DROP"})
	if err := a.verifyForwarding(ctx, state); err == nil {
		t.Fatal("matching wildcard ACL bypass accepted")
	}
}

func TestProxyForwardingConnectedWANSourceIsNeverGranted(t *testing.T) {
	a, _, state := proxyForwardingFixture(t)
	base := a.Runner
	a.Runner = networkCleanupRunner(func(ctx context.Context, name string, args ...string) ([]byte, error) {
		if name == "ip" && strings.Join(args, " ") == "route show table main default" {
			return []byte("default via 192.168.1.1 dev br0"), nil
		}
		return base.Run(ctx, name, args...)
	})
	if _, err := a.compileForwarding(context.Background(), state); err == nil {
		t.Fatal("directly connected WAN source received a forwarding grant")
	}
}

func TestProxyForwardingReadOnlyPreflightDoesNotWriteManifest(t *testing.T) {
	a, r, state := proxyForwardingFixture(t)
	if err := a.preflightForwarding(context.Background(), state); err != nil {
		t.Fatal(err)
	}
	if regularFile(a.forwardingPath()) {
		t.Fatal("preflight acquired ownership")
	}
	for _, call := range r.firewall.calls {
		if !strings.HasSuffix(call, " -S") {
			t.Fatalf("preflight mutated %s", call)
		}
	}
}

func TestProxyForwardingBusyBoxDefaultSelectorReturnsWholeMain(t *testing.T) {
	a, _, state := proxyForwardingFixture(t)
	base := a.Runner
	a.Runner = networkCleanupRunner(func(ctx context.Context, name string, args ...string) ([]byte, error) {
		if name == "ip" && strings.Join(args, " ") == "route show table main default" {
			return []byte("default via 100.64.128.1 dev eth3 metric 1000\n10.8.1.0/24 dev nwg0 scope link src 10.8.1.141\n100.64.128.0/17 dev eth3 scope link src 100.64.181.129\n172.16.1.0/24 dev br1 scope link src 172.16.1.1\n192.168.1.0/24 dev br0 scope link src 192.168.1.1\n"), nil
		}
		return base.Run(ctx, name, args...)
	})
	devices, err := a.forwardingWANInterfaces(context.Background(), false)
	if err != nil || !reflect.DeepEqual(devices, map[string]bool{"eth3": true}) {
		t.Fatalf("BusyBox main table misclassified: %v %v", devices, err)
	}
	if _, err := a.compileForwarding(context.Background(), state); err != nil {
		t.Fatalf("valid LAN source rejected on BusyBox: %v", err)
	}
}

func TestProxyForwardingWANDefaultRejectsUnknownButAcceptsMultipath(t *testing.T) {
	for _, tc := range []struct {
		output string
		ok     bool
	}{
		{"default proto static\n nexthop via 192.0.2.1 dev eth3 weight 1\n nexthop via 192.0.2.2 dev eth4 weight 1\n", true},
		{"default via 192.0.2.1\n", false},
		{"default via 192.0.2.1\n192.168.1.0/24 dev br0\n", false},
		{"unfamiliar route diagnostic\n", false},
	} {
		t.Run(tc.output, func(t *testing.T) {
			a, _, _ := proxyForwardingFixture(t)
			a.Runner = networkCleanupRunner(func(context.Context, string, ...string) ([]byte, error) { return []byte(tc.output), nil })
			_, err := a.forwardingWANInterfaces(context.Background(), false)
			if (err == nil) != tc.ok {
				t.Fatalf("ok=%t err=%v", tc.ok, err)
			}
		})
	}
}

func TestProxyForwardingCommitRecoveryRefreshAndDeactivateShareOwnership(t *testing.T) {
	a, r, state := proxyForwardingFixture(t)
	ctx := context.Background()
	a.Processes = r.processes
	a.EngineBin = "sing-box"
	a.SidecarBin = "sing-box"
	a.SOCKSProbe = func(context.Context, string) error { return nil }
	a.Probe = func(context.Context, string) error { return nil }
	r.processes.running["sing-box-engine"] = true
	r.processes.running["sing-box-tun"] = true
	if err := os.MkdirAll(a.runtimeRoot(), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{a.engineConfigPath(), a.sidecarConfigPath()} {
		if err := os.WriteFile(path, []byte(`{}`), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := a.installForwarding(ctx, state); err != nil {
		t.Fatal(err)
	}
	transaction := t.TempDir()
	policy, _ := json.Marshal(state)
	snapshot, _ := json.Marshal(proxySnapshot{ConfigPath: filepath.Join(transaction, "global.json")})
	for path, data := range map[string][]byte{filepath.Join(transaction, "policy.staged.json"): policy, filepath.Join(transaction, "snapshot.json"): snapshot} {
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := a.Commit(ctx, Plan{}, transaction); err != nil {
		t.Fatal(err)
	}
	committed, exists, err := a.loadPolicy()
	if err != nil || !exists || !samePolicy(committed, state) {
		t.Fatalf("commit lost forwarding ownership: %v", err)
	}
	// A reboot/firewall reload may remove one exact grant while preserving the
	// private lease. Reconcile restores only this adapter's missing rules.
	filter := r.firewall.table("iptables", "filter")
	filter[state.Forwarding.Chain] = filter[state.Forwarding.Chain][1:]
	if err := a.Reconcile(ctx, Plan{}); err != nil {
		t.Fatal(err)
	}
	if err := a.verifyForwarding(ctx, state); err != nil {
		t.Fatal(err)
	}
	plan := Plan{Routes: []Route{{Resolved: "sing-box", Sources: []string{"192.168.1.25/32"}, CIDRs: []string{"198.51.100.21/32"}}}}
	failed := false
	r.firewall.fail = func(call string) bool {
		if !failed && strings.Contains(call, " -A "+state.Forwarding.Chain) && strings.Contains(call, "198.51.100.21/32") {
			failed = true
			return true
		}
		return false
	}
	if updated, err := a.RefreshPolicy(ctx, plan); updated || err == nil {
		t.Fatalf("partial refresh succeeded: updated=%t err=%v", updated, err)
	}
	if err := a.verifyForwarding(ctx, state); err != nil {
		t.Fatalf("failed refresh lost old forwarding: %v", err)
	}
	if updated, err := a.RefreshPolicy(ctx, plan); !updated || err != nil {
		t.Fatalf("refresh failed: updated=%t err=%v", updated, err)
	}
	current, _, err := a.loadPolicy()
	if err != nil || current.Forwarding.Rules[0].Destination != "198.51.100.21/32" {
		t.Fatalf("refresh did not commit new grant: %+v %v", current.Forwarding, err)
	}
	if err := a.verifyForwarding(ctx, current); err != nil {
		t.Fatal(err)
	}
	if err := a.Deactivate(ctx); err != nil {
		t.Fatal(err)
	}
	for _, table := range r.firewall.tables {
		if len(table) != 2 {
			t.Fatalf("deactivate leaked owned chain: %v", table)
		}
	}
	if len(r.processes.running) != 0 || regularFile(a.policyPath()) || regularFile(a.forwardingPath()) {
		t.Fatal("deactivate retained runtime ownership")
	}
}
