package dataplane

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
)

func lanRuntimeFixture(t *testing.T) *LANPolicyRuntimePlan {
	t.Helper()
	p, err := CompileLANPolicyRuntime(strings.Repeat("a", 64), []LANPolicyIngress{{SegmentID: "home", Interface: "br0", Sources: []string{"192.168.1.0/24", "fd00:1::/64"}, ExcludedSources: []string{"192.168.1.40/32"}, ExcludedMACs: []string{"02:00:00:00:00:01"}}})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLANPolicyRuntimeValidationAndDetachedPlan(t *testing.T) {
	p := lanRuntimeFixture(t)
	copy := CloneLANPolicyRuntime(p)
	copy.Ingress[0].ExcludedMACs[0] = "02:00:00:00:00:02"
	if p.Ingress[0].ExcludedMACs[0] != "02:00:00:00:00:01" || ValidateLANPolicyRuntime(copy) == nil {
		t.Fatal("changed binding inherited review authority")
	}
	for name, mutate := range map[string]func(*LANPolicyRuntimePlan){
		"empty generation":  func(p *LANPolicyRuntimePlan) { p.Generation = "" },
		"empty membership":  func(p *LANPolicyRuntimePlan) { p.Ingress[0].Sources = nil },
		"wildcard":          func(p *LANPolicyRuntimePlan) { p.Ingress[0].Interface = "br+" },
		"owned tunnel":      func(p *LANPolicyRuntimePlan) { p.Ingress[0].Interface = "rz-wg" },
		"all source":        func(p *LANPolicyRuntimePlan) { p.Ingress[0].Sources = []string{"0.0.0.0/0"} },
		"zero MAC":          func(p *LANPolicyRuntimePlan) { p.Ingress[0].ExcludedMACs = []string{"00:00:00:00:00:00"} },
		"duplicate ingress": func(p *LANPolicyRuntimePlan) { p.Ingress = append(p.Ingress, p.Ingress[0]) },
	} {
		t.Run(name, func(t *testing.T) {
			bad := CloneLANPolicyRuntime(p)
			mutate(bad)
			if _, err := CompileLANPolicyRuntime(bad.Generation, bad.Ingress); err == nil {
				t.Fatal("invalid gate accepted")
			}
		})
	}
}

func TestLANPolicyRuntimeMACPrecedesBothFamiliesAndPreservesForeignBits(t *testing.T) {
	p := lanRuntimeFixture(t)
	for _, c := range lanPolicyChains(p) {
		macRule := strings.Join(c.rules[1], " ")
		if !strings.Contains(macRule, "--mac-source 02:00:00:00:00:01") || !strings.Contains(macRule, "0x08000000/0x28000000") {
			t.Fatal("future IPv6 privacy address lacks early MAC negative", c)
		}
		last := strings.Join(c.rules[len(c.rules)-1], " ")
		if last != "-j MARK --set-xmark 0x08000000/0x28000000" {
			t.Fatal("outside source inherited admission")
		}
	}
	// Kernel xmark semantics: preserve firmware bits, clear stale owned
	// managed bit, and establish bypass independently of IP leases. Neither
	// the legacy default bit nor WG's endpoint bit belongs to this gate.
	old := uint32(0x11001234) | LANPolicyManagedMark
	got := old & ^uint32(0x28000000) ^ LANPolicyBypassMark
	if got != 0x19001234 || got&LANPolicyManagedMark != 0 || got&0x11000000 != old&0x11000000 {
		t.Fatalf("excluded packet mark %x", got)
	}
	effects, err := p.Effects()
	if err != nil {
		t.Fatal(err)
	}
	published := false
	for _, effect := range effects {
		isJump := strings.Contains(strings.Join(effect.Add, " "), "-I PREROUTING")
		if isJump {
			published = true
		}
		if published && !isJump {
			t.Fatal("chain/rule created after publishing a jump")
		}
		if effect.Tool == "ip" && strings.Contains(strings.Join(effect.Add, " "), "goto") && !strings.Contains(strings.Join(effect.Add, " "), "iif br0") {
			t.Fatal("exclusion changed router/WAN routing")
		}
	}
}

type lanRuntimeReadRunner struct {
	ip       map[string]string
	firewall map[string]string
}

func (r *lanRuntimeReadRunner) Run(_ context.Context, tool string, args ...string) ([]byte, error) {
	if tool == "ip" {
		return []byte(r.ip[args[0]]), nil
	}
	return []byte(r.firewall[tool+":"+args[1]]), nil
}

func lanRuntimeReadFixture(p *LANPolicyRuntimePlan) *lanRuntimeReadRunner {
	r := &lanRuntimeReadRunner{ip: map[string]string{}, firewall: map[string]string{}}
	for _, rule := range lanPolicyRules(p) {
		family := "-4"
		if rule.family == 6 {
			family = "-6"
		}
		r.ip[family] += rule.line() + "\n"
	}
	for _, c := range lanPolicyChains(p) {
		tool := "iptables:mangle"
		if c.family == 6 {
			tool = "ip6tables:mangle"
		}
		r.firewall[tool] += "-N " + c.name + "\n"
		for _, rule := range c.rules {
			r.firewall[tool] += "-A " + c.name + " " + strings.Join(rule, " ") + "\n"
		}
		r.firewall[tool] += "-A PREROUTING " + strings.Join(c.jump, " ") + "\n"
	}
	return r
}

func runtimeWithReadRunner(reader *lanRuntimeReadRunner) *LANPolicyRuntime {
	return &LANPolicyRuntime{Runner: reader, IP: "ip", IPTables: "iptables", IP6Tables: "ip6tables", ScopeCheck: func(context.Context, *LANPolicyRuntimePlan) error { return nil }}
}

func TestLANPolicyRuntimeExactReadbackAndForeignRefusal(t *testing.T) {
	p := lanRuntimeFixture(t)
	reader := lanRuntimeReadFixture(p)
	r := runtimeWithReadRunner(reader)
	if err := r.Verify(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	if err := r.Preflight(context.Background(), p); err == nil {
		t.Fatal("existing tuples adopted")
	}
	for name, mutate := range map[string]func(*lanRuntimeReadRunner){
		"duplicate jump": func(r *lanRuntimeReadRunner) {
			c := lanPolicyChains(p)[0]
			r.firewall["iptables:mangle"] += "-A PREROUTING " + strings.Join(c.jump, " ") + "\n"
		},
		"foreign chain reference": func(r *lanRuntimeReadRunner) {
			c := lanPolicyChains(p)[0]
			r.firewall["iptables:mangle"] += "-A OUTPUT -j " + c.name + "\n"
		},
		"late admission": func(r *lanRuntimeReadRunner) {
			r.firewall["iptables:mangle"] = "-A PREROUTING -j foreign\n" + r.firewall["iptables:mangle"]
		},
		"legacy service":   func(r *lanRuntimeReadRunner) { r.ip["-6"] += "28000: from all to 2001:db8::1 lookup 206\n" },
		"missing positive": func(r *lanRuntimeReadRunner) { r.ip["-4"] += "61: from 192.168.1.0/24 to 8.8.8.8 iif br0 lookup 201\n" },
		"missing iif": func(r *lanRuntimeReadRunner) {
			r.ip["-4"] += "61: from 192.168.1.0/24 to 8.8.8.8 fwmark 0x20000000/0x28000000 lookup 201\n"
		},
		"named legacy table": func(r *lanRuntimeReadRunner) { r.ip["-6"] += "28000: from all to 2001:db8::1 lookup rz-wg\n" },
		"unknown syntax":     func(r *lanRuntimeReadRunner) { r.ip["-4"] += "unparseable RPDB line\n" },
		"late foreign mark": func(r *lanRuntimeReadRunner) {
			r.firewall["ip6tables:mangle"] += "-A OUTPUT -j MARK --set-xmark 0x20000000/0x20000000\n"
		},
		"late connmark": func(r *lanRuntimeReadRunner) {
			r.firewall["iptables:filter"] += "-A FORWARD -j CONNMARK --restore-mark\n"
		},
		"foreign goto anchor": func(r *lanRuntimeReadRunner) { r.ip["-4"] += "111: from all goto 73\n" },
	} {
		t.Run(name, func(t *testing.T) {
			bad := lanRuntimeReadFixture(p)
			mutate(bad)
			if runtimeWithReadRunner(bad).Verify(context.Background(), p) == nil {
				t.Fatal("foreign/missing/order accepted")
			}
		})
	}
	// Positive exact-iif consumer is valid after the gate has activated.
	reader.ip["-4"] += "61: from 192.168.1.0/24 to 8.8.8.8 fwmark 0x20000000/0x28000000 iif br0 lookup 201\n"
	r.ConsumerCheck = func(context.Context, *LANPolicyRuntimePlan) error { return nil }
	if err := r.Verify(context.Background(), p); err != nil {
		t.Fatal(err)
	}
}

func TestLANPolicyRuntimeAnchorAndChainDeletionWaitForAllReferences(t *testing.T) {
	p := lanRuntimeFixture(t)
	reader := lanRuntimeReadFixture(p)
	r := runtimeWithReadRunner(reader)
	effects, _ := p.Effects()
	if err := r.BeforeDelete(context.Background(), p, effects[0]); err == nil {
		t.Fatal("anchor deleted while owned goto referenced it")
	}
	reader.ip["-4"] = strings.ReplaceAll(reader.ip["-4"], lanPolicyRules(p)[1].line()+"\n", "")
	if err := r.BeforeDelete(context.Background(), p, effects[0]); err != nil {
		t.Fatal(err)
	}
	reader.ip["-4"] += "111: from all goto 73\n"
	if err := r.BeforeDelete(context.Background(), p, effects[0]); err == nil {
		t.Fatal("foreign goto anchor silently broken")
	}
	for _, e := range effects {
		if len(e.Add) > 3 && e.Add[2] == "-N" {
			if err := r.BeforeDelete(context.Background(), p, e); err == nil {
				t.Fatal("chain deleted with active contents/references")
			}
			break
		}
	}
}

func TestLANPolicyRuntimeReceiptInspectorDoesNotRequireCurrentReviewForCleanup(t *testing.T) {
	p := lanRuntimeFixture(t)
	r := runtimeWithReadRunner(lanRuntimeReadFixture(p))
	r.ScopeCheck = func(context.Context, *LANPolicyRuntimePlan) error { return ErrReviewChanged }
	effects, _ := p.Effects()
	for _, e := range effects {
		count, foreign, err := r.InspectEffect(context.Background(), p, e)
		if err != nil || foreign || count != 1 {
			t.Fatalf("cleanup inspection %v: %d/%v/%v", e, count, foreign, err)
		}
	}
	bad := effects[0]
	bad.Add = slices.Clone(bad.Add)
	bad.Add[len(bad.Add)-1] = "lookup"
	if _, _, err := r.InspectEffect(context.Background(), p, bad); !errors.Is(err, ErrLANPolicyRuntime) {
		t.Fatal("persisted arbitrary effect accepted")
	}
}

func TestLANPolicyRuntimePreflightCollisionAndNoEffectBeforeAdmission(t *testing.T) {
	p := lanRuntimeFixture(t)
	for name, output := range map[string]string{"fwmark collision": "100: from all fwmark 0x28000000/0x28000000 lookup 4096\n", "full mask": "100: from all fwmark 0x1234 lookup 4096\n", "legacy owner": "28000: from all to 8.8.8.8 lookup 206\n", "named legacy table": "28000: from all to 8.8.8.8 lookup rz-wg\n", "unknown syntax": "unknown RPDB output\n"} {
		t.Run(name, func(t *testing.T) {
			reader := &lanRuntimeReadRunner{ip: map[string]string{"-4": output}, firewall: map[string]string{}}
			r := runtimeWithReadRunner(reader)
			called := false
			r.Execute = func(context.Context, *LANPolicyRuntimePlan, []LANPolicyEffect) error { called = true; return nil }
			if r.Activate(context.Background(), p) == nil || called {
				t.Fatal("colliding gate executed")
			}
		})
	}
	reader := &lanRuntimeReadRunner{ip: map[string]string{"-4": "100: from all fwmark 0x1234/0xffff lookup 4096\n"}, firewall: map[string]string{}}
	if err := runtimeWithReadRunner(reader).Preflight(context.Background(), p); err != nil {
		t.Fatal("disjoint firmware bits rejected", err)
	}
}
