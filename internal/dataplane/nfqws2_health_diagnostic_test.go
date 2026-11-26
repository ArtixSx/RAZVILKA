package dataplane

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ArtixSx/razvilka/internal/engineconfig"
)

func TestNFQWS2HealthDiagnosticClosedReasons(t *testing.T) {
	const owner = "0123456789abcdef01234567"
	stock, err := os.ReadFile(filepath.Join("..", "engineconfig", "testdata", "nfqws2-first-start-1.3.1.conf"))
	if err != nil {
		t.Fatal(err)
	}
	config, err := engineconfig.NFQWSFirstStartConfig(stock, owner, []string{"private-canary.example"}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	running := []byte("ISP_INTERFACE=eth3\nIPV6_ENABLED=0\nTCP_PORTS=443\nUDP_PORTS=\nPOLICY_NAME=nfqws\nPOLICY_EXCLUDE=0\nPOLICY_MARK=\nNFQUEUE_NUM=300\n")
	lease := nfqws2Lease{Owner: owner, ConfigHash: nfqws2Hash(config), FirstStart: &nfqws2FirstStartLease{}}
	if !nfqws2ClosedReachableQueueRule([]byte(nfqwsHealthRulesFixture), config, running, owner) || !nfqws2ClosedReachablePreRule([]byte(nfqwsHealthRulesFixture), config, running, owner) {
		t.Fatal("closed positive fixture must satisfy unchanged acceptance")
	}
	for _, name := range []string{"inventory-command-failed", "inventory-parse-failed", "config-read-failed", "config-missing", "run-read-failed", "run-missing", "lease-config-hash-drift", "main-scope-mismatch", "main-run-scope-mismatch", "post-hook-unreachable", "post-body-mismatch", "pre-hook-unreachable", "pre-body-mismatch"} {
		t.Run(name, func(t *testing.T) {
			data := []byte(nfqwsHealthRulesFixture)
			c, r := append([]byte(nil), config...), append([]byte(nil), running...)
			l := lease
			ce, re, ie := error(nil), error(nil), error(nil)
			cx, rx := true, true
			secret := errors.New("SECRET_TOKEN_PRIVATE_SYSTEM_ERROR")
			switch name {
			case "inventory-command-failed":
				ie = secret
				data = []byte("PRIVATE_RAW_IPTABLES")
			case "inventory-parse-failed":
				data = []byte("PRIVATE_RAW_IPTABLES")
			case "config-read-failed":
				ce = secret
			case "config-missing":
				cx = false
			case "run-read-failed":
				re = secret
			case "run-missing":
				rx = false
			case "lease-config-hash-drift":
				l.ConfigHash = "foreign"
			case "main-scope-mismatch":
				c = []byte("NFQUEUE_NUM=invalid\nSECRET_TOKEN_PRIVATE_SYSTEM_ERROR")
				l.ConfigHash = nfqws2Hash(c)
			case "main-run-scope-mismatch":
				r = []byte(strings.ReplaceAll(string(r), "TCP_PORTS=443", "TCP_PORTS=80"))
			case "post-hook-unreachable":
				data = []byte(strings.ReplaceAll(string(data), "-A POSTROUTING -j nfqws_post\n", ""))
			case "post-body-mismatch":
				data = []byte(strings.ReplaceAll(string(data), "--dports 443", "--dports 80"))
			case "pre-hook-unreachable":
				data = []byte(strings.ReplaceAll(string(data), "-A PREROUTING -j nfqws_pre\n", ""))
			case "pre-body-mismatch":
				data = []byte(strings.ReplaceAll(string(data), "--sports 443", "--sports 80"))
			}
			got := nfqws2HealthRulesDiagnostic(data, ie, c, cx, ce, r, rx, re, &l).Error()
			want := "active NFQWS2 NFQUEUE rules were not confirmed: " + name
			if got != want {
				t.Fatalf("diagnostic=%q want=%q", got, want)
			}
			for _, forbidden := range []string{"SECRET_TOKEN", "PRIVATE_RAW", "private-canary", "*mangle", "-A "} {
				if strings.Contains(got, forbidden) {
					t.Fatal("private observation leaked")
				}
			}
		})
	}
}

func TestNFQWS2HealthDiagnosticExpertDoesNotInventReplyAuthority(t *testing.T) {
	data := []byte(strings.ReplaceAll(nfqwsHealthRulesFixture, "-A PREROUTING -j nfqws_pre\n", ""))
	if !nfqws2ExpertReachableQueueRule(data, []byte(nfqwsHealthMainFixture), []byte(nfqwsHealthRunningFixture)) {
		t.Fatal("expert positive fixture")
	}
	if got := nfqws2HealthRulesReason(data, nil, []byte(nfqwsHealthMainFixture), true, nil, []byte(nfqwsHealthRunningFixture), true, nil, nil); got != "rules-unconfirmed" {
		t.Fatalf("invented expert pre-hook diagnostic: %s", got)
	}
}

func TestNFQWS2HealthDiagnosticDoesNotPublishInventoryOrCommandError(t *testing.T) {
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
			return []byte("PRIVATE_RAW_RULES token=SECRET_TOKEN"), errors.New("PRIVATE_COMMAND_ERROR")
		}
		return runner.Run(ctx, name, args...)
	})
	err := a.Health(context.Background(), Plan{Routes: []Route{{Resolved: "nfqws2", ProbeURL: "https://example.com"}}}, transaction)
	if err == nil || err.Error() != "active NFQWS2 NFQUEUE rules were not confirmed: inventory-command-failed" || probes != 0 {
		t.Fatalf("unexpected health diagnostic/probes: %v/%d", err, probes)
	}
}
