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
	active bool
	calls  []string
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
	if name == "ip" && len(args) >= 3 && args[0] == "route" && args[1] == "get" {
		return []byte(args[2] + " dev rz-warp table 201"), nil
	}
	if name == "wg" && len(args) > 0 && args[0] == "show" {
		return []byte(fmt.Sprintf("peer\t%d\n", time.Now().Unix())), nil
	}
	return []byte("ok"), nil
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
	adapter.WGQuick, adapter.WG, adapter.IP = "wg-quick", "wg", "ip"
	adapter.Runner = runner
	adapter.Resolver = func(_ context.Context, host string) ([]netip.Addr, error) {
		if host == "engage.cloudflareclient.com" {
			return []netip.Addr{netip.MustParseAddr("162.159.192.1")}, nil
		}
		return []netip.Addr{netip.MustParseAddr("198.51.100.20")}, nil
	}
	adapter.HealthProbe = func(context.Context, string) error { return nil }
	transaction := filepath.Join(root, "transaction")
	plan := Plan{Routes: []Route{{ServiceName: "Example", Resolved: "warp-wg", Domains: []string{"example.com"}, ProbeURL: "https://example.com"}}}
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
