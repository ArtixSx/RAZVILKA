package dataplane

import (
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ArtixSx/razvilka/internal/engineconfig"
)

func testOwnWireGuardProfile(extra string) string {
	private := "YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE="
	public := "YmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmI="
	return "[Interface]\nPrivateKey = " + private + "\nAddress = 10.66.0.2/32\n" + extra + "\n[Peer]\nPublicKey = " + public + "\nEndpoint = vpn.example.com:51820\nAllowedIPs = 0.0.0.0/0\nPersistentKeepalive = 25\n"
}

func ownWireGuardFixture(t *testing.T, profile string) (*WARPWireGuardAdapter, *warpFakeRunner, Plan, string) {
	t.Helper()
	root := t.TempDir()
	configs := engineconfig.New(filepath.Join(root, "stage"), filepath.Join(root, "backups"))
	if _, err := configs.Stage("wireguard", "main", profile); err != nil {
		t.Fatal(err)
	}
	runner := &warpFakeRunner{}
	adapter := NewWireGuardAdapter(configs, filepath.Join(root, "state"))
	adapter.RuntimeConfigPath = filepath.Join(root, "runtime", "rz-wg.conf")
	adapter.WG, adapter.IP, adapter.Runner = "wg", "ip", runner
	adapter.Resolver = func(_ context.Context, host string) ([]netip.Addr, error) {
		if host == "vpn.example.com" {
			return []netip.Addr{netip.MustParseAddr("93.184.216.34")}, nil
		}
		return []netip.Addr{netip.MustParseAddr("198.51.100.20")}, nil
	}
	plan := Plan{EngineDrafts: []string{"wireguard/main"}, Routes: []Route{{ServiceName: "Telegram", Resolved: "wireguard", Domains: []string{"telegram.org"}, ProbeURL: "https://telegram.org/"}}}
	return adapter, runner, plan, filepath.Join(root, "transaction")
}

// W01: the own-server WireGuard executor has its own ownership slot, needs no
// Cloudflare registration and never probes a Cloudflare endpoint.
func TestOwnWireGuardCanaryHasNoCloudflareDependency(t *testing.T) {
	adapter, runner, plan, transaction := ownWireGuardFixture(t, testOwnWireGuardProfile(""))
	var probes []string
	adapter.CanaryProbe = func(_ context.Context, rawURL, source string) error {
		if source != "10.66.0.2" {
			t.Fatalf("canary source=%q", source)
		}
		probes = append(probes, rawURL)
		return nil
	}
	for _, step := range []func(context.Context, Plan, string) error{adapter.Snapshot, adapter.Stage, adapter.Validate} {
		if err := step(context.Background(), plan, transaction); err != nil {
			t.Fatal(err)
		}
	}
	if err := adapter.Canary(context.Background(), plan.RoutePlanFor("wireguard"), transaction); err != nil {
		t.Fatal(err)
	}
	if len(probes) != 1 || probes[0] != "https://telegram.org/" {
		t.Fatalf("own WireGuard probed %v", probes)
	}
	joined := strings.Join(runner.calls, "\n")
	for _, required := range []string{"wg setconf rz-wg-canary", "ip link delete dev rz-wg-canary"} {
		if !strings.Contains(joined, required) {
			t.Fatalf("canary call missing %q:\n%s", required, joined)
		}
	}
	if strings.Contains(joined, "2408") || strings.Contains(joined, "rz-warp") {
		t.Fatalf("own WireGuard touched WARP resources:\n%s", joined)
	}
	if adapter.ID() != "wireguard" || adapterID("wireguard") != "wireguard" || AdapterID("wireguard") != "wireguard" {
		t.Fatal("route is not mapped to the wireguard adapter")
	}
}

func TestOwnWireGuardRefusesAmneziaFieldsAndHooks(t *testing.T) {
	for name, extra := range map[string]string{"amnezia junk": "Jc = 4\nJmin = 40\nJmax = 70", "hook": "PostUp = iptables -F"} {
		adapter, _, plan, transaction := ownWireGuardFixture(t, testOwnWireGuardProfile(""))
		if err := adapter.Snapshot(context.Background(), plan, transaction); err != nil {
			t.Fatal(err)
		}
		if _, err := adapter.Configs.Stage("wireguard", "main", testOwnWireGuardProfile(extra)); err == nil {
			// The editor may accept syntax; the transaction must still refuse.
			if err := adapter.Snapshot(context.Background(), plan, transaction); err != nil {
				t.Fatal(err)
			}
			if err := adapter.Stage(context.Background(), plan, transaction); err == nil {
				t.Fatalf("%s accepted by the plain WireGuard executor", name)
			}
		}
		if validation := engineconfig.ValidateContent("wireguard", "main", testOwnWireGuardProfile(extra)); validation.OK {
			t.Fatalf("%s passed plain WireGuard validation", name)
		}
	}
}

// The ownership contract must stay disjoint: tables, interfaces, rule ranges
// and shared slots of every adapter never overlap.
func TestPolicyOwnershipSpecsAreDisjoint(t *testing.T) {
	specs := PolicyOwnershipSpecs()
	seen := map[string]bool{}
	for i, a := range specs {
		for _, key := range []string{"adapter:" + a.Adapter, "if:" + a.Interface, "table:" + string(rune(a.Table))} {
			if seen[key] {
				t.Fatalf("duplicate %s", key)
			}
			seen[key] = true
		}
		for _, b := range specs[i+1:] {
			if a.PriorityBase <= b.PriorityEnd && b.PriorityBase <= a.PriorityEnd || a.SharedPriorityBase <= b.SharedPriorityEnd && b.SharedPriorityBase <= a.SharedPriorityEnd {
				t.Fatalf("%s and %s share rule priorities", a.Adapter, b.Adapter)
			}
		}
	}
	state := PolicyState{Interface: "rz-wg", Table: 206, PriorityBase: 28000}
	initializePolicyLayout(&state)
	if state.RuleLayout != 2 || state.SharedPriorityBase != 70 {
		t.Fatalf("own WireGuard layout not allocated from the contract: %+v", state)
	}
}

// W02: the runtime profile carries the same resolved server address as the
// endpoint exclusion; a name resolving to a private address is refused.
func TestOwnWireGuardPinsResolvedEndpoint(t *testing.T) {
	adapter, _, plan, transaction := ownWireGuardFixture(t, testOwnWireGuardProfile(""))
	if err := adapter.Snapshot(context.Background(), plan, transaction); err != nil {
		t.Fatal(err)
	}
	if err := adapter.Stage(context.Background(), plan, transaction); err != nil {
		t.Fatal(err)
	}
	staged, err := os.ReadFile(filepath.Join(transaction, "rz-warp.conf.staged"))
	if err != nil || !strings.Contains(string(staged), "Endpoint = 93.184.216.34:51820") || strings.Contains(string(staged), "vpn.example.com") {
		t.Fatalf("endpoint not pinned: %s %v", staged, err)
	}
	adapter, _, plan, transaction = ownWireGuardFixture(t, testOwnWireGuardProfile(""))
	adapter.Resolver = func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("192.168.1.50")}, nil
	}
	if err := adapter.Snapshot(context.Background(), plan, transaction); err != nil {
		t.Fatal(err)
	}
	if err := adapter.Stage(context.Background(), plan, transaction); err == nil || !strings.Contains(err.Error(), "WireGuard server address") {
		t.Fatalf("private server address accepted: %v", err)
	}
}
