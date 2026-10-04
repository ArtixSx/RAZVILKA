package dataplane

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"
)

func managedPolicyFixture() PolicyState {
	state := testEarlyPolicy()
	state.NetworkPolicyGeneration = strings.Repeat("a", 64)
	state.NetworkDefault = true
	state.Rules = []PolicyRule{
		{Source: "192.168.1.40/32", Destination: "149.154.167.99/32", Ingress: "br0", Managed: true},
		{Source: "192.168.2.40/32", Destination: "149.154.167.99/32", Ingress: "br1", Managed: true},
		{Source: "fd00:1::40/128", Destination: "2001:db8::99/128", Ingress: "br0", Managed: true},
	}
	state.Prefixes = []string{"149.154.167.99/32", "2001:db8::99/128"}
	state.Exclusions = []string{"203.0.113.9/32", "2001:db8::9/128"}
	return state
}

func TestManagedPolicyReceiptBindsExactIngressAndMarkInBothFamilies(t *testing.T) {
	_, root, runner, options := additionFixture(t)
	state := managedPolicyFixture()
	initializePolicyLayout(&state)
	ctx := context.Background()
	if err := applyPolicyAddition(ctx, runner, "ip", state, root, options); err != nil {
		t.Fatal(err)
	}
	expected, err := kernelRulesForPolicy(state)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range runner.kernel.entries {
		if entry.ingress == "" || entry.mark != LANPolicyGateMatch || entry.source == "all" {
			t.Fatal("managed selector broadened", entry)
		}
	}
	for _, family := range []int{4, 6} {
		lines, err := readPolicyRules(ctx, runner, "ip", family)
		if err != nil {
			t.Fatal(err)
		}
		wanted, priorities := map[kernelPolicyRule]bool{}, map[int]bool{}
		for _, rule := range expected {
			if rule.family == family {
				wanted[rule], priorities[rule.priority] = true, true
			}
		}
		matched := map[kernelPolicyRule]bool{}
		for _, line := range lines {
			priority, hasPriority := policyLinePriority(line)
			if !hasPriority || !priorities[priority] {
				continue
			}
			rule, ok := parseKernelPolicyRule(family, line)
			if !ok || !wanted[rule] || !rule.managed || rule.ingress == "" || matched[rule] {
				t.Fatal("owned readback lost exact gate or duplicated tuple", line)
			}
			matched[rule] = true
		}
		for want := range wanted {
			if !matched[want] {
				t.Fatal("family missing exact owned rule", family, want)
			}
		}
	}
	doc := readAdditionFixture(t, state, root, options)
	for _, step := range doc.Steps[2:] {
		if !strings.Contains(strings.Join(step.Add, " "), "fwmark "+LANPolicyGateMatch+" iif ") || !strings.Contains(strings.Join(step.Delete, " "), "fwmark "+LANPolicyGateMatch+" iif ") {
			t.Fatal("receipt omitted selector", step)
		}
	}
	if err := removePolicyAddition(ctx, runner, "ip", state, root, options); err != nil {
		t.Fatal(err)
	}
	if len(runner.kernel.entries) != 0 || len(runner.kernel.defaults) != 0 {
		t.Fatal("owned effects remain", runner.kernel)
	}
}

func TestManagedPolicyDefaultDependencyIncludesForeignIngress(t *testing.T) {
	_, root, runner, options := additionFixture(t)
	state := managedPolicyFixture()
	if err := applyPolicyAddition(context.Background(), runner, "ip", state, root, options); err != nil {
		t.Fatal(err)
	}
	foreign := runner.kernel.entries[0]
	for _, entry := range runner.kernel.entries {
		if entry.table == "203" {
			foreign = entry
			break
		}
	}
	foreign.ingress = "foreign0"
	// Model completed cleanup of the known children. A different iif still
	// references their parent table; it grants no right to delete that child.
	runner.kernel.entries = []policyKernelEntry{foreign}
	if err := AssertPolicyDefaultUnreferenced(context.Background(), &dependencyTestReader{runner}, "ip", state, 4); !errors.Is(err, ErrPolicyDefaultReferenced) {
		t.Fatal("foreign iif dependency ignored", err)
	}
	if !reflect.DeepEqual([]policyKernelEntry{foreign}, runner.kernel.entries) || len(runner.kernel.defaults) != 2 {
		t.Fatal("read-only dependency check changed foreign selector or default", runner.kernel)
	}
}

func TestManagedPolicyParserRejectsExtraOrChangedSelectors(t *testing.T) {
	good := "65: from 192.168.1.40 to 149.154.167.99 fwmark " + LANPolicyGateMatch + " iif br0 lookup 203"
	rule, ok := parseKernelPolicyRule(4, good)
	if !ok || !rule.managed || rule.ingress != "br0" {
		t.Fatal("exact managed readback rejected")
	}
	for _, line := range []string{
		strings.Replace(good, LANPolicyGateMatch, "0x20000000", 1),
		strings.Replace(good, "iif br0", "iif lo", 1),
		strings.Replace(good, "iif br0", "iif br0 iif br1", 1),
		strings.Replace(good, "iif br0", "iif br0 oif rz-sing", 1),
		good + " suppress_prefixlength 0", good + " proto static",
		strings.Replace(good, "from", "not from", 1),
	} {
		if _, ok := parseKernelPolicyRule(4, line); ok {
			t.Fatal("near-match gained ownership", line)
		}
	}
}

func TestManagedPolicyPrecedenceProvesOnlyPositiveDisjointConstraints(t *testing.T) {
	rules, err := kernelRulesForPolicy(managedPolicyFixture())
	if err != nil {
		t.Fatal(err)
	}
	target := rules[len(rules)-3]
	for _, tc := range []struct {
		line    string
		overlap bool
	}{
		{"40: from all iif wan0 lookup 4096", false},
		{"40: from all iif br0 lookup 4096", true},
		{"40: not from all iif wan0 lookup 4096", true},
		{"40: from all iif wan0 iif br0 lookup 4096", true},
		{"53: from all fwmark 0x8000000/0x8000000 iif br0 goto 73", false},
		{"40: from all fwmark 0x20000000/0x28000000 iif br0 lookup 4096", true},
		{"40: from all fwmark 0x1/0x1 iif br0 lookup 4096", true},
	} {
		if got := policyLineMayOverlap(tc.line, target); got != tc.overlap {
			t.Fatalf("%s overlap=%t want%t", tc.line, got, tc.overlap)
		}
	}
}

func TestPolicySourceDeduplicationPreservesIngressBoundary(t *testing.T) {
	for _, reverse := range []bool{false, true} {
		routes := []Route{
			{Resolved: "sing-box", CIDRs: []string{"198.51.100.20/32"}, Ingress: []string{"br0"}},
			{Resolved: "sing-box", CIDRs: []string{"198.51.100.20/32"}, Sources: []string{"192.168.2.25/32"}, Ingress: []string{"br1"}},
		}
		if reverse {
			routes[0], routes[1] = routes[1], routes[0]
		}
		_, rules, err := resolvePolicyRules(context.Background(), Plan{Routes: routes}, "sing-box", nil)
		if err != nil || len(rules) != 2 {
			t.Fatal("iif-scoped source collapsed", rules, err)
		}
		routes = append(routes, Route{Resolved: "sing-box", CIDRs: []string{"198.51.100.20/32"}})
		_, rules, err = resolvePolicyRules(context.Background(), Plan{Routes: routes}, "sing-box", nil)
		if err != nil || len(rules) != 1 || rules[0].Ingress != "" {
			t.Fatal("legacy global semantics changed", rules, err)
		}
	}
}

func TestManagedForwardingRejectsIngressDriftAndPreservesReturnContract(t *testing.T) {
	a, _, state := proxyForwardingFixture(t)
	state.Rules[0].Ingress = "br1"
	if _, err := a.compileForwarding(context.Background(), state); !errors.Is(err, ErrNetworkPolicyAuthority) {
		t.Fatal("reverse source silently replaced reviewed iif", err)
	}
	state.Rules[0].Ingress = "br0"
	state.Rules[0].Managed = true
	state.NetworkPolicyGeneration = strings.Repeat("a", 64)
	initializePolicyLayout(&state)
	forwarding, err := a.compileForwarding(context.Background(), state)
	if err != nil {
		t.Fatal(err)
	}
	state.Forwarding = forwarding
	for _, table := range proxyFirewallTables(state) {
		for _, jump := range table.jumps {
			joined := strings.Join(jump, " ")
			if strings.Contains(joined, "--ctstate") {
				if strings.Contains(joined, "--mark") {
					t.Fatal("reply incorrectly required physical LAN skb mark", joined)
				}
			} else if !strings.Contains(joined, "--mark "+LANPolicyGateMatch) {
				t.Fatal("outbound grant lacks positive gate", joined)
			}
		}
	}
}

func TestManagedForwardingCapacityDoesNotWidenLegacyOrInvalidPolicy(t *testing.T) {
	a, _, state := proxyForwardingFixture(t)
	state.Rules = nil
	for i := 0; i < 129; i++ {
		state.Rules = append(state.Rules, PolicyRule{Source: "192.168.1.25/32", Destination: fmt.Sprintf("198.51.100.%d/32", i), Ingress: "br0", Managed: true})
	}
	state.NetworkPolicyGeneration = strings.Repeat("b", 64)
	initializePolicyLayout(&state)
	if _, err := a.compileForwarding(context.Background(), state); err != nil {
		t.Fatal("bounded managed complement rejected", err)
	}
	state.NetworkPolicyGeneration = ""
	for i := range state.Rules {
		state.Rules[i].Managed = false
	}
	if _, err := a.compileForwarding(context.Background(), state); err == nil {
		t.Fatal("legacy forwarding bound silently widened")
	}
	state.NetworkPolicyGeneration = strings.Repeat("b", 64)
	if proxyForwardingRuleLimit(state) != 128 {
		t.Fatal("invalid mark scope gained expanded bound")
	}
}

func TestNetworkPolicyRouteShapeIsStrictAndDigestBindsIngress(t *testing.T) {
	route := Route{ServiceID: "site", Resolved: "sing-box", CIDRs: []string{"198.51.100.20/32"}, Sources: []string{"192.168.1.25/32"}, Ingress: []string{"br0"}, NetworkPolicyGeneration: strings.Repeat("a", 64), NetworkPolicyRole: "default"}
	for _, bad := range []string{"generation", "role", "source", "domain", "duplicate-ingress", "mixed-legacy"} {
		t.Run(bad, func(t *testing.T) {
			r := route
			routes := []Route{r}
			switch bad {
			case "generation":
				routes[0].NetworkPolicyGeneration = strings.Repeat("A", 64)
			case "role":
				routes[0].NetworkPolicyRole = "unknown"
			case "source":
				routes[0].Sources = []string{"0.0.0.0/0"}
			case "domain":
				routes[0].Domains = []string{"example.org"}
			case "duplicate-ingress":
				routes[0].Ingress = []string{"br0", "br0"}
			case "mixed-legacy":
				routes = append(routes, Route{Resolved: "sing-box", CIDRs: r.CIDRs})
			}
			if _, _, err := NetworkPolicyRouteAuthority(Plan{Routes: routes}, "sing-box"); !errors.Is(err, ErrNetworkPolicyAuthority) {
				t.Fatal("invalid shape accepted", err)
			}
		})
	}
	planA, err := BuildAt(Input{SafeMode: true, Routes: []Route{route}}, time.Unix(1, 0))
	if err != nil {
		t.Fatal(err)
	}
	route.Ingress = []string{"br1"}
	planB, err := BuildAt(Input{SafeMode: true, Routes: []Route{route}}, time.Unix(1, 0))
	if err != nil || planA.Digest == planB.Digest {
		t.Fatal("review digest dropped physical ingress", err)
	}
}
