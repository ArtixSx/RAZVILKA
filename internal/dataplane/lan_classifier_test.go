package dataplane

import (
	"slices"
	"strings"
	"testing"
)

func lanClassifierFixture() LANClassifierState {
	return LANClassifierState{Chain: "RZC_0123456789ab", Ingress: []string{"br0"},
		ExcludedSources: []string{"192.168.1.40/32", "fd00::40/128"}, ExcludedMACs: []string{"AA:BB:CC:DD:EE:0F"},
		DirectDestinations: []string{"95.163.0.0/16", "2a00:1450::/32"}, DefaultTable: 203}
}

func TestLANClassifierValidation(t *testing.T) {
	if err := validLANClassifier(lanClassifierFixture()); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*LANClassifierState){
		"chain":         func(s *LANClassifierState) { s.Chain = "PREROUTING" },
		"no ingress":    func(s *LANClassifierState) { s.Ingress = nil },
		"wildcard":      func(s *LANClassifierState) { s.Ingress = []string{"br+"} },
		"default route": func(s *LANClassifierState) { s.DirectDestinations = []string{"0.0.0.0/0"} },
		"unmasked":      func(s *LANClassifierState) { s.ExcludedSources = []string{"192.168.1.40/24"} },
		"duplicate":     func(s *LANClassifierState) { s.ExcludedSources = []string{"192.168.1.40/32", "192.168.1.40/32"} },
		"lowercase MAC": func(s *LANClassifierState) { s.ExcludedMACs = []string{"aa:bb:cc:dd:ee:0f"} },
		"multicast MAC": func(s *LANClassifierState) { s.ExcludedMACs = []string{"01:00:5E:00:00:01"} },
		"table":         func(s *LANClassifierState) { s.DefaultTable = 254 },
		"MAC without path": func(s *LANClassifierState) {
			s.DefaultTable, s.DirectDestinations = 0, nil
		},
	} {
		s := lanClassifierFixture()
		mutate(&s)
		if validLANClassifier(s) == nil {
			t.Errorf("%s accepted", name)
		}
	}
	exclusionsOnly := LANClassifierState{Chain: "RZC_0123456789ab", Ingress: []string{"br0"}, ExcludedSources: []string{"192.168.1.40/32"}}
	if err := validLANClassifier(exclusionsOnly); err != nil {
		t.Fatal("exclusions without a default path rejected:", err)
	}
}

// The chain returns already-marked packets first, then exclusions, local and
// direct destinations, and marks the rest last.
func TestLANClassifierChainOrder(t *testing.T) {
	s := lanClassifierFixture()
	v4 := lanClassifierChainRules(s, false)
	first, last := strings.Join(v4[0], " "), strings.Join(v4[len(v4)-1], " ")
	if first != "-m mark ! --mark 0x0 -j RETURN" || last != "-j MARK --set-xmark 0x10000000/0x10000000" {
		t.Fatalf("order: %q ... %q", first, last)
	}
	joined := func(rules [][]string) string {
		lines := []string{}
		for _, r := range rules {
			lines = append(lines, strings.Join(r, " "))
		}
		return strings.Join(lines, "\n")
	}
	text := joined(v4)
	for _, want := range []string{"-s 192.168.1.40/32 -j RETURN", "-m mac --mac-source AA:BB:CC:DD:EE:0F -j RETURN", "-d 192.168.0.0/16 -j RETURN", "-d 95.163.0.0/16 -j RETURN"} {
		if !strings.Contains(text, want) {
			t.Fatalf("missing %q in\n%s", want, text)
		}
	}
	if strings.Contains(text, "fd00::") || strings.Contains(text, "2a00:") {
		t.Fatal("IPv6 prefix in IPv4 chain")
	}
	v6 := joined(lanClassifierChainRules(s, true))
	if !strings.Contains(v6, "-s fd00::40/128") || !strings.Contains(v6, "-d fe80::/10") || strings.Contains(v6, "192.168.") {
		t.Fatalf("IPv6 chain wrong:\n%s", v6)
	}
	if got := lanClassifierJumps(s); len(got) != 1 || strings.Join(got[0], " ") != "-i br0 -j RZC_0123456789ab" {
		t.Fatalf("jumps: %v", got)
	}
	s.DefaultTable, s.ExcludedMACs, s.DirectDestinations = 0, nil, nil
	if lanClassifierChainRules(s, false) != nil || lanClassifierJumps(s) != nil {
		t.Fatal("exclusions-only classifier created a chain")
	}
}

func TestLANClassifierPolicyRulesAndArgs(t *testing.T) {
	s := lanClassifierFixture()
	rules := lanClassifierPolicyRules(s)
	lines := []string{}
	for _, r := range rules {
		lines = append(lines, r.line())
	}
	want := []string{"59: from 192.168.1.40 goto 72", "59: from fd00::40 goto 72", "72: from all fwmark 0x10000000/0x10000000 lookup 203", "72: from all fwmark 0x10000000/0x10000000 lookup 203"}
	if !slices.Equal(lines, want) {
		t.Fatalf("lines %q", lines)
	}
	if got := strings.Join(rules[0].args("add"), " "); got != "-4 rule add priority 59 from 192.168.1.40/32 goto 72" {
		t.Fatalf("args %q", got)
	}
	if got := strings.Join(rules[3].args("del"), " "); got != "-6 rule del priority 72 fwmark 0x10000000/0x10000000 lookup 203" {
		t.Fatalf("args %q", got)
	}
	// Exclusions only: the anchor is a nop, and only in families with a goto.
	s.DefaultTable, s.ExcludedMACs, s.DirectDestinations, s.ExcludedSources = 0, nil, nil, []string{"192.168.1.40/32"}
	rules = lanClassifierPolicyRules(s)
	if len(rules) != 2 || rules[1].line() != "72: from all nop" || rules[1].family != 4 {
		t.Fatalf("exclusions-only rules %+v", rules)
	}
}

// Output formats observed on the owner's Keenetic (iproute2 ss4.4, 29.09.2026).
func TestLANClassifierRuleReadback(t *testing.T) {
	s := lanClassifierFixture()
	expected := lanClassifierPolicyRules(s)
	output := "0:\tfrom all lookup local \n59:\tfrom 192.168.1.40 goto 72\n72:\tfrom all fwmark 0x10000000/0x10000000 lookup 203 \n100:\tfrom all fwmark 0xffffaaa lookup 4096 \n32766:\tfrom all lookup main \n"
	if missing, foreign := lanClassifierRuleReadback(output, expected, 4); len(missing) != 0 || len(foreign) != 0 {
		t.Fatalf("clean readback: %v %v", missing, foreign)
	}
	missing, foreign := lanClassifierRuleReadback("59:\tfrom 192.168.1.99 goto 72\n", expected, 4)
	if len(missing) != 2 || len(foreign) != 1 || foreign[0] != "59: from 192.168.1.99 goto 72" {
		t.Fatalf("foreign/missing: %v %v", missing, foreign)
	}
}

func TestLANClassifierChainReadback(t *testing.T) {
	s := lanClassifierFixture()
	expected := lanClassifierChainRules(s, false)
	lines := []string{"-N RZC_0123456789ab"}
	for _, rule := range expected {
		// iptables prints single hosts as /32 and MACs in upper case.
		lines = append(lines, "-A RZC_0123456789ab "+strings.Join(rule, " "))
	}
	output := strings.Join(lines, "\n")
	if err := lanClassifierChainReadback(output, s.Chain, expected); err != nil {
		t.Fatal(err)
	}
	if lanClassifierChainReadback(strings.Replace(output, "-N RZC_0123456789ab", "", 1), s.Chain, expected) == nil {
		t.Fatal("missing chain accepted")
	}
	reordered := append([]string{lines[0], lines[len(lines)-1]}, lines[1:len(lines)-1]...)
	if lanClassifierChainReadback(strings.Join(reordered, "\n"), s.Chain, expected) == nil {
		t.Fatal("mark rule moved before exclusions accepted")
	}
	if lanClassifierChainReadback(output+"\n-A RZC_0123456789ab -s 10.0.0.9/32 -j ACCEPT", s.Chain, expected) == nil {
		t.Fatal("foreign rule accepted")
	}
	if lanClassifierChainKey([]string{"-s", "192.168.1.40", "-j", "RETURN"}) != lanClassifierChainKey([]string{"-s", "192.168.1.40/32", "-j", "RETURN"}) {
		t.Fatal("host prefix not normalized")
	}
}
