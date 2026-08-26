package dataplane

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/engineconfig"
)

type warpFakeRunner struct {
	active                bool
	calls                 []string
	starts                int
	handshakeAfterRestart bool
	neverHandshake        bool
}

func (r *warpFakeRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	r.calls = append(r.calls, name+" "+strings.Join(args, " "))
	if name == "wg-quick" && len(args) > 0 {
		if args[0] == "up" {
			r.active = true
		} else if args[0] == "down" {
			r.active = false
		}
		return []byte("ok"), nil
	}
	if name == "ip" && len(args) >= 4 && args[0] == "link" && args[1] == "show" {
		if r.active {
			return []byte("rz-warp: UP"), nil
		}
		return nil, fmt.Errorf("device not found")
	}
	if name == "ip" && len(args) >= 2 && args[0] == "link" && args[1] == "add" {
		r.active = true
		r.starts++
		return []byte("ok"), nil
	}
	if name == "ip" && len(args) >= 2 && args[0] == "link" && args[1] == "delete" {
		r.active = false
		return []byte("ok"), nil
	}
	if name == "ip" && len(args) >= 3 && args[0] == "route" && args[1] == "get" {
		return []byte(args[2] + " dev rz-warp table 201"), nil
	}
	if name == "wg" && len(args) > 0 && args[0] == "show" {
		if r.neverHandshake || (r.handshakeAfterRestart && r.starts < 2) {
			return []byte("peer\t0\n"), nil
		}
		return []byte(fmt.Sprintf("peer\t%d\n", time.Now().Unix())), nil
	}
	return []byte("ok"), nil
}

func TestWARPHandshakeTriesOfficialFallbackPortsAndPersistsWinner(t *testing.T) {
	root := t.TempDir()
	configs := engineconfig.New(filepath.Join(root, "stage"), filepath.Join(root, "backups"))
	if _, err := configs.Stage("warp-wg", "main", testWARPProfile()); err != nil {
		t.Fatal(err)
	}
	runner := &warpFakeRunner{handshakeAfterRestart: true}
	adapter := NewWARPWireGuardAdapter(configs, filepath.Join(root, "state"))
	adapter.RuntimeConfigPath = filepath.Join(root, "runtime", "rz-warp.conf")
	adapter.WG, adapter.IP = "wg", "ip"
	adapter.Runner = runner
	adapter.HandshakeTimeout = time.Millisecond
	adapter.FallbackPorts = []int{500, 4500}
	adapter.Resolver = func(_ context.Context, host string) ([]netip.Addr, error) {
		if host == "engage.cloudflareclient.com" {
			return []netip.Addr{netip.MustParseAddr("162.159.192.1")}, nil
		}
		return []netip.Addr{netip.MustParseAddr("198.51.100.20")}, nil
	}
	adapter.HealthProbe = func(context.Context, string) error { return nil }
	transaction := filepath.Join(root, "transaction")
	plan := Plan{EngineDrafts: []string{"warp-wg/main"}, Routes: []Route{{ServiceName: "Telegram", Resolved: "warp-wg", Domains: []string{"telegram.org"}, ProbeURL: "https://telegram.org/"}}}
	if err := adapter.Snapshot(context.Background(), plan, transaction); err != nil {
		t.Fatal(err)
	}
	snapshot, err := readWarpWGSnapshot(transaction)
	if err != nil {
		t.Fatal(err)
	}
	snapshot.ProfilePath = filepath.Join(root, "live", "wgcf-profile.conf")
	snapshotData, _ := json.Marshal(snapshot)
	if err := os.WriteFile(filepath.Join(transaction, "snapshot.json"), snapshotData, 0o600); err != nil {
		t.Fatal(err)
	}
	steps := []struct {
		name   string
		action func() error
	}{
		{"stage", func() error { return adapter.Stage(context.Background(), plan, transaction) }},
		{"validate", func() error { return adapter.Validate(context.Background(), plan, transaction) }},
		{"activate", func() error { return adapter.Activate(context.Background(), plan, transaction) }},
		{"health", func() error { return adapter.Health(context.Background(), plan, transaction) }},
		{"commit", func() error { return adapter.Commit(context.Background(), plan, transaction) }},
	}
	for _, step := range steps {
		if err := step.action(); err != nil {
			t.Fatalf("%s: %v", step.name, err)
		}
	}
	live, err := os.ReadFile(snapshot.ProfilePath)
	if err != nil || !strings.Contains(string(live), "Endpoint = engage.cloudflareclient.com:500") {
		t.Fatalf("fallback endpoint was not committed: content=%q err=%v", live, err)
	}
}

func TestWARPHandshakeFailureDoesNotExposePeerKey(t *testing.T) {
	runner := &warpFakeRunner{active: true, neverHandshake: true}
	adapter := NewWARPWireGuardAdapter(nil, t.TempDir())
	adapter.WG, adapter.IP = "wg", "ip"
	adapter.Runner = runner
	adapter.HandshakeTimeout = time.Millisecond
	err := adapter.confirmHandshake(context.Background(), "rz-warp")
	if err == nil || strings.Contains(err.Error(), "peer") || !strings.Contains(err.Error(), "handshake") {
		t.Fatalf("unexpected handshake error: %v", err)
	}
}

func TestSanitizeWGQuickProfileRemovesExecutableHooks(t *testing.T) {
	profile := strings.Replace(testWARPProfile(), "Address = 172.16.0.2/32\n", "Address = 172.16.0.2/32\nPostUp = touch /tmp/unsafe\nDNS = 1.1.1.1\nTable = auto\n", 1)
	got, err := sanitizeWGQuickProfile(profile)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(got, "PostUp") || strings.Contains(got, "DNS =") || strings.Contains(got, "Table = auto") || strings.Count(got, "Table = off") != 1 {
		t.Fatalf("unsafe wg-quick profile=%q", got)
	}
}

func TestNativeWGConfigSeparatesInterfaceSettingsFromSecrets(t *testing.T) {
	profile := strings.Replace(testWARPProfile(), "Address = 172.16.0.2/32\n", "Address = 172.16.0.2/32, 2606:4700:110::2/128\nDNS = 1.1.1.1\nMTU = 1280\nTable = off\n", 1)
	setconf, addresses, mtu, err := nativeWGConfig(profile)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(setconf, "Address =") || strings.Contains(setconf, "DNS =") || strings.Contains(setconf, "MTU =") || strings.Contains(setconf, "Table =") {
		t.Fatalf("wg setconf received wg-quick-only fields: %q", setconf)
	}
	if !strings.Contains(setconf, "PrivateKey =") || !strings.Contains(setconf, "PublicKey =") {
		t.Fatalf("wg configuration lost required keys: %q", setconf)
	}
	if len(addresses) != 2 || mtu != 1280 {
		t.Fatalf("native settings addresses=%v mtu=%d", addresses, mtu)
	}
}

func TestAmneziaProfileValidationAndOwnership(t *testing.T) {
	profile := strings.Replace(testWARPProfile(), "Address = 172.16.0.2/32\n", "Address = 172.16.0.2/32\nJc = 4\nJmin = 64\nJmax = 128\nS1 = 0\nS2 = 0\nH1 = 1\nH2 = 2\nH3 = 3\nH4 = 4\n", 1)
	if err := validateAmneziaProfile(profile); err != nil {
		t.Fatal(err)
	}
	invalid := strings.Replace(profile, "Jmin = 64", "Jmin = 256", 1)
	if err := validateAmneziaProfile(strings.Replace(invalid, "Jmax = 128", "Jmax = 128", 1)); err == nil {
		t.Fatal("Jmin > Jmax was accepted")
	}
	adapter := NewAmneziaWGAdapter(nil, t.TempDir())
	if adapter.ID() != "amneziawg" || adapter.Interface != "rz-awg" || adapter.Table != 205 {
		t.Fatalf("unexpected AmneziaWG ownership: %+v", adapter)
	}
}

func TestWARPAdapterActivatesHealthChecksAndRollsBack(t *testing.T) {
	root := t.TempDir()
	configs := engineconfig.New(filepath.Join(root, "stage"), filepath.Join(root, "backups"))
	if _, err := configs.Stage("warp-wg", "main", testWARPProfile()); err != nil {
		t.Fatal(err)
	}
	runner := &warpFakeRunner{}
	adapter := NewWARPWireGuardAdapter(configs, filepath.Join(root, "state"))
	adapter.RuntimeConfigPath = filepath.Join(root, "runtime", "rz-warp.conf")
	adapter.WG, adapter.IP = "wg", "ip"
	adapter.Runner = runner
	adapter.Resolver = func(_ context.Context, host string) ([]netip.Addr, error) {
		if host == "engage.cloudflareclient.com" {
			return []netip.Addr{netip.MustParseAddr("162.159.192.1")}, nil
		}
		return []netip.Addr{netip.MustParseAddr("198.51.100.20")}, nil
	}
	adapter.HealthProbe = func(context.Context, string) error { return nil }
	transaction := filepath.Join(root, "transaction")
	plan := Plan{EngineDrafts: []string{"warp-wg/main"}, Routes: []Route{{ServiceName: "Example", Resolved: "warp-wg", Domains: []string{"example.com"}, ProbeURL: "https://example.com"}}}
	if err := adapter.Snapshot(context.Background(), plan, transaction); err != nil {
		t.Fatal(err)
	}
	if err := adapter.Stage(context.Background(), plan, transaction); err != nil {
		t.Fatal(err)
	}
	if err := adapter.Validate(context.Background(), plan, transaction); err != nil {
		t.Fatal(err)
	}
	if err := adapter.Activate(context.Background(), plan, transaction); err != nil {
		t.Fatal(err)
	}
	if err := adapter.Health(context.Background(), plan, transaction); err != nil {
		t.Fatal(err)
	}
	if !runner.active {
		t.Fatal("WARP candidate interface was not activated")
	}
	if joined := strings.Join(runner.calls, "\n"); !strings.Contains(joined, "wg setconf rz-warp") || strings.Contains(joined, "wg-quick up") {
		t.Fatalf("native Entware activation was not used:\n%s", joined)
	}
	if err := adapter.Rollback(context.Background(), plan, transaction); err != nil {
		t.Fatal(err)
	}
	if runner.active {
		t.Fatal("WARP candidate interface remained active after rollback")
	}
	content, err := configs.ReadExpert("warp-wg", "main")
	if err != nil || content.Source != "staged" {
		t.Fatalf("profile draft was not preserved: %+v err=%v", content, err)
	}
}

func TestWARPDeactivateRemovesOnlyOwnedRuntime(t *testing.T) {
	root := t.TempDir()
	runner := &warpFakeRunner{active: true}
	adapter := NewWARPWireGuardAdapter(engineconfig.New(filepath.Join(root, "stage"), filepath.Join(root, "backups")), filepath.Join(root, "state"))
	adapter.RuntimeConfigPath = filepath.Join(root, "runtime", "rz-warp.conf")
	adapter.WGQuick, adapter.WG, adapter.IP = "wg-quick", "wg", "ip"
	adapter.Runner = runner
	if err := os.MkdirAll(filepath.Dir(adapter.RuntimeConfigPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(adapter.RuntimeConfigPath, []byte(testWARPProfile()), 0o600); err != nil {
		t.Fatal(err)
	}
	policy := PolicyState{Interface: adapter.Interface, Table: adapter.Table, PriorityBase: adapter.PriorityBase, Prefixes: []string{"198.51.100.20/32"}}
	data, _ := json.Marshal(policy)
	if err := os.MkdirAll(adapter.StateRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(adapter.statePath(), data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := adapter.Deactivate(context.Background()); err != nil {
		t.Fatal(err)
	}
	if runner.active {
		t.Fatal("owned interface remains active")
	}
	for _, path := range []string{adapter.statePath(), adapter.RuntimeConfigPath} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("owned runtime file remains: %s", path)
		}
	}
}

func testWARPProfile() string {
	key := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	return "[Interface]\nPrivateKey = " + key + "\nAddress = 172.16.0.2/32\n\n[Peer]\nPublicKey = " + key + "\nEndpoint = engage.cloudflareclient.com:2408\nAllowedIPs = 0.0.0.0/0, ::/0\n"
}
