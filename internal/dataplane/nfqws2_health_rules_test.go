package dataplane

import (
	"context"
	"errors"
	"fmt"
	"github.com/ArtixSx/razvilka/internal/engineconfig"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Stock iptables-save formatting, including normalized extension-option order.
const nfqwsHealthMainFixture = "ISP_INTERFACE=eth3\nNFQUEUE_NUM=300\nTCP_PORTS=443\nUDP_PORTS=\nPOLICY_NAME=nfqws\nPOLICY_EXCLUDE=0\n"
const nfqwsHealthRunningFixture = nfqwsHealthMainFixture + "POLICY_MARK=\n"
const nfqwsHealthRulesFixture = `*mangle
:POSTROUTING ACCEPT [0:0]
:nfqws_post - [0:0]
-A POSTROUTING -j nfqws_post
-A nfqws_post -o eth3 -p tcp -m mark ! --mark 0x40000000/0x40000000 -m multiport --dports 443 -m connbytes --connbytes 1:15 --connbytes-mode packets --connbytes-dir original -j NFQUEUE --queue-num 300 --queue-bypass
-A nfqws_post -o eth3 -p tcp -m mark ! --mark 0x40000000/0x40000000 -m multiport --dports 443 -m tcp --tcp-flags FIN FIN -j NFQUEUE --queue-num 300 --queue-bypass
-A nfqws_post -o eth3 -p tcp -m mark ! --mark 0x40000000/0x40000000 -m multiport --dports 443 -m tcp --tcp-flags RST RST -j NFQUEUE --queue-num 300 --queue-bypass
COMMIT
`

func TestNFQWS2HealthRequiresReachableOwnedQueueBeforeWebProbe(t *testing.T) {
	// Reduced verbatim structure of the router observation: an empty stock
	// nat chain and the independent firmware delay queue are both present.
	firmwareOnly := "*nat\n:POSTROUTING ACCEPT [0:0]\n:nfqws_nat - [0:0]\n-A POSTROUTING -j nfqws_nat\nCOMMIT\n*mangle\n:OUTPUT ACCEPT [0:0]\n:POSTROUTING ACCEPT [0:0]\n:_NDM_OUTPUT_DELAY - [0:0]\n-A OUTPUT -j _NDM_OUTPUT_DELAY\n-A _NDM_OUTPUT_DELAY ! -s 127.0.0.1/32 ! -d 127.0.0.1/32 -m ndmmark --ndmmark 0x0/0x80 -j NFQUEUE --queue-num 64511\nCOMMIT\n"
	for _, tc := range []struct {
		name, rules string
		accepted    bool
	}{
		{"owned-path", nfqwsHealthRulesFixture, true},
		{"config-drift-during-inventory", nfqwsHealthRulesFixture, false},
		{"router-firmware-queue-and-empty-nat-chain", firmwareOnly, false},
		{"stale-running-process-no-queue", "*mangle\n:POSTROUTING ACCEPT [0:0]\nCOMMIT\n", false},
		{"wrong-queue", strings.ReplaceAll(nfqwsHealthRulesFixture, "--queue-num 300", "--queue-num 301"), false},
		{"udp-only", strings.ReplaceAll(nfqwsHealthRulesFixture, "-p tcp", "-p udp"), false},
		{"other-tcp-port", strings.ReplaceAll(nfqwsHealthRulesFixture, "--dports 443", "--dports 80"), false},
		{"foreign-chain", strings.ReplaceAll(nfqwsHealthRulesFixture, "nfqws_post", "foreign"), false},
		{"orphan-owned-chain", strings.ReplaceAll(nfqwsHealthRulesFixture, "-A POSTROUTING -j nfqws_post\n", ""), false},
		{"conditional-hook", strings.ReplaceAll(nfqwsHealthRulesFixture, "-A POSTROUTING -j", "-A POSTROUTING -o eth3 -j"), false},
		{"terminal-before-hook", strings.ReplaceAll(nfqwsHealthRulesFixture, "-A POSTROUTING -j nfqws_post", "-A POSTROUTING -j ACCEPT\n-A POSTROUTING -j nfqws_post"), false},
		{"return-before-queue", strings.Replace(nfqwsHealthRulesFixture, "-A nfqws_post", "-A nfqws_post -j RETURN\n-A nfqws_post", 1), false},
		{"other-table", strings.ReplaceAll(nfqwsHealthRulesFixture, "*mangle", "*nat"), false},
		{"unfinished-table", strings.ReplaceAll(nfqwsHealthRulesFixture, "COMMIT\n", ""), false},
		{"empty-foreign-hook", strings.ReplaceAll(nfqwsHealthRulesFixture, ":nfqws_post - [0:0]", ":nfqws_post - [0:0]\n:vendor - [0:0]\n-A POSTROUTING -j vendor"), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, runner, root := newOwnedNFQWS2(t)
			a.IPTablesSave = "iptables-save"
			transaction := stageOwnedNFQWS2(t, a, root, "old.example")
			if err := a.Activate(context.Background(), Plan{}, transaction); err != nil {
				t.Fatal(err)
			}
			probes := 0
			a.HealthProbe = func(context.Context, string) error { probes++; return nil }
			a.Runner = nfqws2RunFunc(func(ctx context.Context, name string, args ...string) ([]byte, error) {
				if name == a.IPTablesSave {
					if tc.name == "config-drift-during-inventory" {
						writeStockText(t, a.ConfigPath, readText(t, a.ConfigPath)+"# foreign edit\n")
					}
					return []byte(tc.rules), nil
				}
				if name != a.InitPath || len(args) != 1 || args[0] != "status" {
					return nil, errors.New("health attempted an unexpected command")
				}
				return runner.Run(ctx, name, args...)
			})
			plan := Plan{Routes: []Route{{ServiceID: "example", ServiceName: "Example", Resolved: "nfqws2", ProbeURL: "https://example.com"}}}
			err := a.Health(context.Background(), plan, transaction)
			if (err == nil) != tc.accepted || probes != map[bool]int{true: 1, false: 0}[tc.accepted] {
				t.Fatalf("accepted=%v err=%v probes=%d", tc.accepted, err, probes)
			}
		})
	}
}

func TestNFQWS2FirstStartHealthRefusesRetainedLivePIDWithoutOwnedQueue(t *testing.T) {
	if firstStartNamespace(t) {
		return
	}
	f := newFirstStartFixture(t)
	f.apply(t)
	// Keep the exact original modelled runtime identity and lease live. A
	// firmware rule reset must not let their presence substitute for a path.
	f.ownedRules = false
	probes := 0
	f.a.HealthProbe = func(context.Context, string) error { probes++; return nil }
	err := f.a.Health(firstStartContext(t), f.plan, "")
	if err == nil || !strings.Contains(err.Error(), "NFQUEUE rules were not confirmed") || probes != 0 || !f.running {
		t.Fatalf("missing owned queue: err=%v probes=%d running=%v", err, probes, f.running)
	}
}

// These are literal stock command/save shapes, not rules rendered by the
// production matcher. Policy include has all three stock early-return rules;
// policy exclude has only its positive mark RETURN.
const nfqwsHealthPolicyHTTPRules = `*mangle
:POSTROUTING ACCEPT [0:0]
:nfqws_post - [0:0]
-A POSTROUTING -j nfqws_post
-A nfqws_post -o eth3 -m mark ! --mark 0x123/0xfffffff -j CONNMARK --set-xmark 0x20000000/0x20000000
-A nfqws_post -o eth3 -m connmark --mark 0x20000000/0x20000000 -j RETURN
-A nfqws_post -o eth3 -m mark ! --mark 0x123/0xfffffff -j RETURN
-A nfqws_post -o eth3 -p tcp -m mark ! --mark 0x40000000/0x40000000 -m multiport --dports 80 -m connbytes --connbytes 1:15 --connbytes-mode packets --connbytes-dir original -j NFQUEUE --queue-num 301 --queue-bypass
-A nfqws_post -o eth3 -p tcp -m mark ! --mark 0x40000000/0x40000000 -m multiport --dports 80 -m tcp --tcp-flags FIN FIN -j NFQUEUE --queue-num 301 --queue-bypass
-A nfqws_post -o eth3 -p tcp -m mark ! --mark 0x40000000/0x40000000 -m multiport --dports 80 -m tcp --tcp-flags RST RST -j NFQUEUE --queue-num 301 --queue-bypass
COMMIT
`
const nfqwsHealthPolicyUDPRules = `*mangle
:POSTROUTING ACCEPT [0:0]
:nfqws_post - [0:0]
-A POSTROUTING -j nfqws_post
-A nfqws_post -o eth3 -m mark --mark 0x123/0xfffffff -j RETURN
-A nfqws_post -o eth3 -p udp -m mark ! --mark 0x40000000/0x40000000 -m multiport --dports 443,500:550 -m connbytes --connbytes 1:15 --connbytes-mode packets --connbytes-dir original -j NFQUEUE --queue-num 301 --queue-bypass
COMMIT
`

func TestNFQWS2ExpertHealthBindsStockPolicyHTTPAndUDPPaths(t *testing.T) {
	const main = "ISP_INTERFACE=eth3\nNFQUEUE_NUM=301\nTCP_PORTS=80\nUDP_PORTS=\nPOLICY_NAME=nfqws\nPOLICY_EXCLUDE=0\n"
	const running = main + "POLICY_MARK=\"0x123/0x0fffffff\"\n"
	for _, tc := range []struct {
		name, config, run, rules string
		accepted                 bool
	}{
		{"policy-include-http", main, running, nfqwsHealthPolicyHTTPRules, true},
		{"policy-include-low-mask", main, strings.ReplaceAll(running, "0x123/0x0fffffff", "0x10/0xff"), strings.ReplaceAll(nfqwsHealthPolicyHTTPRules, "0x123/0xfffffff", "0x10/0xff"), true},
		{"policy-zero-value", main, strings.ReplaceAll(running, "0x123/0x0fffffff", "0x0/0xff"), strings.ReplaceAll(nfqwsHealthPolicyHTTPRules, "0x123/0xfffffff", "0x0/0xff"), true},
		{"zero-policy-mask", main, strings.ReplaceAll(running, "0x123/0x0fffffff", "0x0/0x0"), strings.ReplaceAll(nfqwsHealthPolicyHTTPRules, "0x123/0xfffffff", "0x0/0x0"), false},
		{"value-outside-low-mask", main, strings.ReplaceAll(running, "0x123/0x0fffffff", "0x100/0xff"), strings.ReplaceAll(nfqwsHealthPolicyHTTPRules, "0x123/0xfffffff", "0x100/0xff"), false},
		{"value-outside-mask-hole", main, strings.ReplaceAll(running, "0x123/0x0fffffff", "0x3/0x5"), strings.ReplaceAll(nfqwsHealthPolicyHTTPRules, "0x123/0xfffffff", "0x3/0x5"), false},
		{"foreign-queue", main, running, strings.ReplaceAll(nfqwsHealthPolicyHTTPRules, "--queue-num 301", "--queue-num 302"), false},
		{"missing-jump", main, running, strings.ReplaceAll(nfqwsHealthPolicyHTTPRules, "-A POSTROUTING -j nfqws_post\n", ""), false},
		{"unknown-return", main, running, strings.Replace(nfqwsHealthPolicyHTTPRules, "-A nfqws_post", "-A nfqws_post -j RETURN\n-A nfqws_post", 1), false},
		{"wrong-policy-mask", main, running, strings.ReplaceAll(nfqwsHealthPolicyHTTPRules, "0x123/0xfffffff", "0x123/0xffffffff"), false},
		{"wrong-policy-polarity", main, running, strings.ReplaceAll(nfqwsHealthPolicyHTTPRules, "! --mark 0x123", "--mark 0x123"), false},
		{"wrong-connmark-mask", main, running, strings.ReplaceAll(nfqwsHealthPolicyHTTPRules, "--set-xmark 0x20000000/0x20000000", "--set-xmark 0x20000000/0xffffffff"), false},
		{"wrong-iface", main, running, strings.ReplaceAll(nfqwsHealthPolicyHTTPRules, "-o eth3", "-o eth4"), false},
		{"wrong-ports", main, running, strings.ReplaceAll(nfqwsHealthPolicyHTTPRules, "--dports 80", "--dports 443"), false},
		{"missing-packet-window", main, running, strings.ReplaceAll(nfqwsHealthPolicyHTTPRules, "-m connbytes --connbytes 1:15 --connbytes-mode packets --connbytes-dir original ", ""), false},
		{"mixed-queue", main, running, strings.Replace(nfqwsHealthPolicyHTTPRules, "--queue-num 301", "--queue-num 302", 1), false},
		{"unreviewed-match", main, running, strings.Replace(nfqwsHealthPolicyHTTPRules, "-o eth3", "-s 192.0.2.1 -o eth3", 1), false},
		{"overlay-port-drift", main, strings.ReplaceAll(running, "TCP_PORTS=80", "TCP_PORTS=443"), nfqwsHealthPolicyHTTPRules, false},
		{"overlay-iface-drift", main, strings.ReplaceAll(running, "ISP_INTERFACE=eth3", "ISP_INTERFACE=eth4"), nfqwsHealthPolicyHTTPRules, false},
		{"overlay-policy-drift", main, strings.ReplaceAll(running, "POLICY_EXCLUDE=0", "POLICY_EXCLUDE=1"), nfqwsHealthPolicyHTTPRules, false},
		{"unreachable-processed-policy", main, strings.ReplaceAll(running, "0x123/0x0fffffff", "0x40000000/0x40000000"), strings.ReplaceAll(nfqwsHealthPolicyHTTPRules, "0x123/0xfffffff", "0x40000000/0x40000000"), false},
		{"invalid-policy-value", main, strings.ReplaceAll(running, "0x123/0x0fffffff", "0x40000000/0x0fffffff"), strings.ReplaceAll(nfqwsHealthPolicyHTTPRules, "0x123/0xfffffff", "0x40000000/0xfffffff"), false},
		{"overlay-mark-drift", main, strings.ReplaceAll(running, "0x123/0x0fffffff", "0x124/0x0fffffff"), nfqwsHealthPolicyHTTPRules, false},
		{"missing-overlay", main, "", nfqwsHealthPolicyHTTPRules, false},
		{"main-nonliteral-scope", strings.ReplaceAll(main, "TCP_PORTS=80", "PORTS=80\nTCP_PORTS=$PORTS"), running, nfqwsHealthPolicyHTTPRules, false},
		{"duplicate-overlay", main, running + "TCP_PORTS=80\n", nfqwsHealthPolicyHTTPRules, false},
		{"multiline-strategy-boundary", "NFQWS_ARGS=\"line one\nTCP_PORTS=443\nline three\"\n" + main, running, nfqwsHealthPolicyHTTPRules, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, runner, root := newOwnedNFQWS2(t)
			writeStockText(t, a.ConfigPath, tc.config)
			writeStockText(t, a.ConfigPath+".run", tc.run)
			transaction := stageOwnedNFQWS2(t, a, root, "policy.example")
			if err := a.Activate(context.Background(), Plan{}, transaction); err != nil {
				t.Fatal(err)
			}
			a.IPTablesSave = "iptables-save"
			probes := 0
			a.HealthProbe = func(context.Context, string) error { probes++; return nil }
			a.Runner = nfqws2RunFunc(func(ctx context.Context, name string, args ...string) ([]byte, error) {
				if name == a.IPTablesSave {
					return []byte(tc.rules), nil
				}
				return runner.Run(ctx, name, args...)
			})
			plan := Plan{Routes: []Route{{Resolved: "nfqws2", ProbeURL: "http://policy.example", ServiceName: "HTTP"}}}
			err := a.Health(context.Background(), plan, transaction)
			if (err == nil) != tc.accepted || probes != map[bool]int{true: 1, false: 0}[tc.accepted] {
				t.Fatalf("accepted=%v err=%v probes=%d", tc.accepted, err, probes)
			}
		})
	}
	for _, exclude := range []bool{false, true} {
		t.Run(fmt.Sprintf("policy-udp-exclude-%v", exclude), func(t *testing.T) {
			config := strings.ReplaceAll(strings.ReplaceAll(main, "TCP_PORTS=80", "TCP_PORTS="), "UDP_PORTS=", "UDP_PORTS=443,500:550")
			rules := nfqwsHealthPolicyUDPRules
			if exclude {
				config = strings.ReplaceAll(config, "POLICY_EXCLUDE=0", "POLICY_EXCLUDE=1")
			} else {
				rules = strings.Replace(rules, "-A nfqws_post -o eth3 -m mark --mark 0x123/0xfffffff -j RETURN\n", "-A nfqws_post -o eth3 -m mark ! --mark 0x123/0xfffffff -j CONNMARK --set-xmark 0x20000000/0x20000000\n-A nfqws_post -o eth3 -m connmark --mark 0x20000000/0x20000000 -j RETURN\n-A nfqws_post -o eth3 -m mark ! --mark 0x123/0xfffffff -j RETURN\n", 1)
			}
			if !nfqws2ExpertReachableQueueRule([]byte(rules), []byte(config), []byte(config+"POLICY_MARK=0x123/0x0fffffff\n")) {
				t.Fatal("valid UDP policy path refused")
			}
			if nfqws2ReachableQueueRule([]byte(rules), "301") {
				t.Fatal("closed starter accepted expert UDP policy rules")
			}
		})
	}
}

func TestNFQWS2ClosedHealthBindsExactInterfaceAndProcessedMark(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "engineconfig", "testdata", "nfqws2-first-start-1.3.1.conf"))
	if err != nil {
		t.Fatal(err)
	}
	const owner = "111111111111111111111111"
	config, err := engineconfig.NFQWSFirstStartConfig(raw, owner, []string{"service.example"}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	run := []byte("ISP_INTERFACE=eth3\nIPV6_ENABLED=0\nTCP_PORTS=443\nUDP_PORTS=\nPOLICY_NAME=nfqws\nPOLICY_EXCLUDE=0\nPOLICY_MARK=\nNFQUEUE_NUM=300\n")
	for _, tc := range []struct {
		name, rules string
		accepted    bool
	}{
		{"closed-stock", nfqwsHealthRulesFixture, true},
		{"wrong-interface", strings.ReplaceAll(nfqwsHealthRulesFixture, "-o eth3", "-o eth4"), false},
		{"wrong-processed-mark", strings.ReplaceAll(nfqwsHealthRulesFixture, "0x40000000/0x40000000", "0x20000000/0x20000000"), false},
		{"processed-mark-not-negated", strings.ReplaceAll(nfqwsHealthRulesFixture, "! --mark", "--mark"), false},
		{"missing-interface", strings.ReplaceAll(nfqwsHealthRulesFixture, "-o eth3 ", ""), false},
		{"extra-match", strings.ReplaceAll(nfqwsHealthRulesFixture, "-o eth3", "-o eth3 -s 192.0.2.1"), false},
		{"missing-bypass", strings.ReplaceAll(nfqwsHealthRulesFixture, " --queue-bypass", ""), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := nfqws2ClosedReachableQueueRule([]byte(tc.rules), config, run, owner); got != tc.accepted {
				t.Fatalf("got %v want %v", got, tc.accepted)
			}
		})
	}
	if nfqws2ClosedReachableQueueRule([]byte(nfqwsHealthRulesFixture), config, []byte(strings.ReplaceAll(string(run), "POLICY_MARK=\n", "POLICY_MARK=0x10/0xff\n")), owner) {
		t.Fatal("closed policy scope expanded")
	}
}

func TestNFQWS2FirstStartHealthRefusesOwnedKernelScopeDrift(t *testing.T) {
	if firstStartNamespace(t) {
		return
	}
	for _, kind := range []string{"interface", "processed-mark"} {
		t.Run(kind, func(t *testing.T) {
			f := newFirstStartFixture(t)
			f.apply(t)
			rules := strings.ReplaceAll(nfqwsHealthRulesFixture, "-o eth3", "-o eth4")
			if kind == "processed-mark" {
				rules = strings.ReplaceAll(nfqwsHealthRulesFixture, "0x40000000/0x40000000", "0x20000000/0x20000000")
			}
			original := f.a.Runner
			f.a.Runner = nfqws2RunFunc(func(ctx context.Context, name string, args ...string) ([]byte, error) {
				if name == f.a.IPTablesSave {
					return []byte(rules), nil
				}
				return original.Run(ctx, name, args...)
			})
			probes := 0
			f.a.HealthProbe = func(context.Context, string) error { probes++; return nil }
			if err := f.a.Health(firstStartContext(t), f.plan, ""); err == nil || probes != 0 || !f.running {
				t.Fatalf("kernel drift accepted: %v probes=%d running=%v", err, probes, f.running)
			}
		})
	}
}
