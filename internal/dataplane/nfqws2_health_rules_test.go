package dataplane

import (
	"context"
	"errors"
	"strings"
	"testing"
)

const nfqwsHealthRulesFixture = "*mangle\n:POSTROUTING ACCEPT [0:0]\n:nfqws_post - [0:0]\n-A POSTROUTING -j nfqws_post\n-A nfqws_post -p tcp -m multiport --dports 443 -j NFQUEUE --queue-num 300\nCOMMIT\n"

func TestNFQWS2HealthRequiresReachableOwnedQueueBeforeWebProbe(t *testing.T) {
	// Reduced verbatim structure of the router observation: an empty stock
	// nat chain and the independent firmware delay queue are both present.
	firmwareOnly := "*nat\n:POSTROUTING ACCEPT [0:0]\n:nfqws_nat - [0:0]\n-A POSTROUTING -j nfqws_nat\nCOMMIT\n*mangle\n:OUTPUT ACCEPT [0:0]\n:POSTROUTING ACCEPT [0:0]\n:_NDM_OUTPUT_DELAY - [0:0]\n-A OUTPUT -j _NDM_OUTPUT_DELAY\n-A _NDM_OUTPUT_DELAY ! -s 127.0.0.1/32 ! -d 127.0.0.1/32 -m ndmmark --ndmmark 0x0/0x80 -j NFQUEUE --queue-num 64511\nCOMMIT\n"
	for _, tc := range []struct {
		name, rules string
		accepted    bool
	}{
		{"owned-path", nfqwsHealthRulesFixture, true},
		{"router-firmware-queue-and-empty-nat-chain", firmwareOnly, false},
		{"stale-running-process-no-queue", "*mangle\n:POSTROUTING ACCEPT [0:0]\nCOMMIT\n", false},
		{"wrong-queue", strings.ReplaceAll(nfqwsHealthRulesFixture, "--queue-num 300", "--queue-num 301"), false},
		{"udp-only", strings.ReplaceAll(nfqwsHealthRulesFixture, "-p tcp", "-p udp"), false},
		{"other-tcp-port", strings.ReplaceAll(nfqwsHealthRulesFixture, "--dports 443", "--dports 80"), false},
		{"foreign-chain", strings.ReplaceAll(nfqwsHealthRulesFixture, "nfqws_post", "foreign"), false},
		{"orphan-owned-chain", strings.ReplaceAll(nfqwsHealthRulesFixture, "-A POSTROUTING -j nfqws_post\n", ""), false},
		{"conditional-hook", strings.ReplaceAll(nfqwsHealthRulesFixture, "-A POSTROUTING -j", "-A POSTROUTING -o eth3 -j"), false},
		{"terminal-before-hook", strings.ReplaceAll(nfqwsHealthRulesFixture, "-A POSTROUTING -j nfqws_post", "-A POSTROUTING -j ACCEPT\n-A POSTROUTING -j nfqws_post"), false},
		{"return-before-queue", strings.ReplaceAll(nfqwsHealthRulesFixture, "-A nfqws_post -p", "-A nfqws_post -j RETURN\n-A nfqws_post -p"), false},
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
