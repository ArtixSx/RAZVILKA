//go:build linux

package dataplane

import (
	"context"
	"os"
	"os/exec"
	"slices"
	"strings"
	"testing"
	"time"
)

// This opt-in harness runs real legacy iptables in its own fresh network
// namespace: the restore argv must read back through -S token for token as
// the classifier expects, iptables-save must pass Health's closed post and
// pre proofs, and the cleanup inverse must leave the exact prior tables. No
// host rule, interface or process is touched. It is legacy 1.8 evidence, not
// a claim about the router's 1.4.21 binary.
func TestNFQWS2HookGraphRoundTripsNativeLegacy(t *testing.T) {
	if os.Getenv("RAZVILKA_HOOK_NETNS") != "1" {
		t.Skip("explicit isolated native opt-in: RAZVILKA_HOOK_NETNS=1")
	}
	if os.Geteuid() != 0 {
		t.Fatal("native hook harness requires root")
	}
	if os.Getenv("RAZVILKA_HOOK_NETNS_PARENT") == "" {
		parent, err := os.Readlink("/proc/self/ns/net")
		if err != nil {
			t.Fatal(err)
		}
		binary, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		cmd := exec.CommandContext(ctx, "unshare", "--net", "--", binary, "-test.run=^TestNFQWS2HookGraphRoundTripsNativeLegacy$", "-test.count=1", "-test.v")
		cmd.Env = append(os.Environ(), "RAZVILKA_HOOK_NETNS_PARENT="+parent)
		output, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("fresh namespace harness failed: %v\n%s", err, output)
		}
		t.Logf("fresh namespace results:\n%s", output)
		return
	}
	if current, err := os.Readlink("/proc/self/ns/net"); err != nil || current == os.Getenv("RAZVILKA_HOOK_NETNS_PARENT") {
		t.Fatal("refusing mutations outside a fresh network namespace", err)
	}
	tools := map[int]string{}
	for family, name := range map[int]string{4: "iptables-legacy", 6: "ip6tables-legacy"} {
		path, err := exec.LookPath(name)
		if err != nil {
			t.Fatal("required native tool unavailable", name, err)
		}
		tools[family] = path
	}
	save, err := exec.LookPath("iptables-legacy-save")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	run := func(family int, args ...string) {
		t.Helper()
		if output, err := runFirewallCommand(ctx, nfqws2ExecRunner{}, tools[family], args...); err != nil {
			t.Fatalf("%v: %v\n%s", args, err, output)
		}
	}
	// A sanitized firmware prelude: a RETURN chain and an empty chain before
	// the hooks, and the verify-only nat state stock leaves.
	for _, family := range []int{4, 6} {
		run(family, "-t", "mangle", "-N", "_NDM_HOTSPOT")
		run(family, "-t", "mangle", "-A", "_NDM_HOTSPOT", "-s", map[int]string{4: "192.0.2.1/32", 6: "2001:db8::1/128"}[family], "-j", "RETURN")
		run(family, "-t", "mangle", "-A", "PREROUTING", "-j", "_NDM_HOTSPOT")
		run(family, "-t", "mangle", "-N", "_NDM_POSTROUTING_TTL")
		run(family, "-t", "mangle", "-A", "POSTROUTING", "-j", "_NDM_POSTROUTING_TTL")
	}
	run(4, "-t", "nat", "-N", "nfqws_nat")
	run(4, "-t", "nat", "-A", "POSTROUTING", "-j", "nfqws_nat")
	read := func() BackendInventorySnapshot {
		t.Helper()
		var rows []BackendInventoryRow
		var budget backendClassicBudget
		for _, table := range []struct {
			family int
			name   string
		}{{4, "filter"}, {4, "mangle"}, {4, "nat"}, {6, "filter"}, {6, "mangle"}} {
			output, err := exec.CommandContext(ctx, tools[table.family], "-t", table.name, "-S").Output()
			if err != nil {
				t.Fatal(err)
			}
			parsed, err := backendXTablesRows(output, &budget)
			if err != nil {
				t.Fatal(err)
			}
			for _, tokens := range parsed {
				rows = append(rows, BackendInventoryRow{Family: table.family, Table: table.name, Tokens: tokens})
			}
		}
		identity, _ := networkPolicyIdentityFixture()
		return networkPolicyInventoryTestImage(identity.value, rows)
	}
	graph := nfqws2HookTestGraph(t, true)
	config := nfqws2HookTestConfig(t, func(raw string) string { return strings.Replace(raw, "IPV6_ENABLED=0", "IPV6_ENABLED=1", 1) })
	running := []byte(strings.Replace(nfqws2RouterRunFixture, "IPV6_ENABLED=0", "IPV6_ENABLED=1", 1))
	loss := read()
	if c := nfqws2ClassifyHookGraph(graph, loss); c.Class != nfqws2HookLoss || !slices.Equal(c.restore(), []int{4, 6}) {
		t.Fatal("native firmware prelude is not the loss signature", c.Class, c.Reason)
	}
	// The restore order: chains and bodies of every family, then the jumps.
	attempted := map[int][]BackendInventoryRow{}
	for _, g := range graph.Families {
		for _, chain := range g.Chains {
			run(g.Family, "-t", "mangle", "-N", chain)
			attempted[g.Family] = append(attempted[g.Family], BackendInventoryRow{Family: g.Family, Table: "mangle", Tokens: []string{"-N", chain}})
		}
		for _, rule := range g.Bodies {
			run(g.Family, append([]string{"-t", "mangle"}, rule.tokens()...)...)
			attempted[g.Family] = append(attempted[g.Family], BackendInventoryRow{Family: g.Family, Table: "mangle", Tokens: rule.tokens()})
		}
	}
	for _, g := range graph.Families {
		for _, jump := range g.Jumps {
			run(g.Family, append([]string{"-t", "mangle"}, jump.tokens()...)...)
			attempted[g.Family] = append(attempted[g.Family], BackendInventoryRow{Family: g.Family, Table: "mangle", Tokens: jump.tokens()})
		}
	}
	full := read()
	if c := nfqws2ClassifyHookGraph(graph, full); c.Class != nfqws2HookFull {
		t.Fatalf("restored argv does not read back token for token: %v\n%v", c.Reason, full.Rows)
	}
	remainder, ok := nfqws2HookWithout(full.Rows, append(slices.Clone(attempted[4]), attempted[6]...))
	if !ok || !nfqws2HookSameRows(remainder, loss.Rows) {
		t.Fatal("restore changed rows beside its own")
	}
	image, err := exec.CommandContext(ctx, save).Output()
	if err != nil {
		t.Fatal(err)
	}
	if !nfqws2ClosedReachableQueueRule(image, config, running, nfqws2HookTestOwner) || !nfqws2ClosedReachablePreRule(image, config, running, nfqws2HookTestOwner) {
		t.Fatalf("native iptables-save fails the closed Health proofs:\n%s", image)
	}
	removals, ok := nfqws2HookCleanup(full.Rows, []int{4, 6}, attempted)
	if !ok || len(removals) != 24 {
		t.Fatal("cleanup selection", len(removals), ok)
	}
	for _, row := range removals {
		run(row.Family, nfqws2HookRemoval(row)...)
	}
	if after := read(); !nfqws2HookSameRows(after.Rows, loss.Rows) {
		t.Fatal("cleanup inverse did not restore the exact prior tables", after.Rows)
	}
}
