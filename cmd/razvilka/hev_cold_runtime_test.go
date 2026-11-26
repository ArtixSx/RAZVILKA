package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/ArtixSx/razvilka/internal/backendprofile"
	"github.com/ArtixSx/razvilka/internal/components"
	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/dataplane"
)

func hevColdFixture(t *testing.T) (string, string, *components.Manager) {
	t.Helper()
	root := t.TempDir()
	cfg := filepath.Join(root, "config.json")
	state := filepath.Join(root, "dataplane")
	owner := components.New()
	owner.StateDir = filepath.Join(root, "components")
	owner.BinDir = filepath.Join(root, "absent-bin")
	return cfg, state, owner
}
func hevColdWriteConfig(t *testing.T, path, choice string) {
	t.Helper()
	cfg := config.Default()
	cfg.ProxySidecar = choice
	raw, _ := json.Marshal(cfg)
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
}
func hevColdWriteSidecar(t *testing.T, state, id string) {
	t.Helper()
	iface, address, port := "rz-sing", "172.31.21.1/30", 18081
	if id == "usque" {
		iface, address, port = "rz-usque", "172.31.20.1/30", 18080
	}
	raw, err := backendprofile.HevJSON(backendprofile.HevOptions{Interface: iface, Address: address, SOCKSPort: port, MTU: 1400, MaxSessions: 128})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(state, id, "runtime", "sidecar.json")
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
}
func hevColdAssertOwners(t *testing.T, m *dataplane.Manager, owner *components.Manager) {
	t.Helper()
	for _, id := range []string{"usque", "sing-box", "xray"} {
		a, ok := m.Adapters[id].(*dataplane.ProxyTunnelAdapter)
		if !ok || a.SidecarKind != "hev" || a.SidecarBin != filepath.Join(owner.BinDir, "hev-socks5-tunnel") {
			t.Fatalf("cold %s changed original backend: %+v", id, a)
		}
	}
}

func TestHEVColdRecoveryReconstructsStoredChoiceWithoutInstalledExecutable(t *testing.T) {
	cfg, state, owner := hevColdFixture(t)
	hevColdWriteConfig(t, cfg, "hev")
	hevColdWriteSidecar(t, state, "sing-box")
	m, err := newColdDataplaneManager(context.Background(), state, nil, cfg, owner)
	if err != nil {
		t.Fatal("cold cleanup required installed binary", err)
	}
	hevColdAssertOwners(t, m, owner)
	if _, err := os.Stat(owner.BinDir); !os.IsNotExist(err) {
		t.Fatal("cold construction initialized binary path", err)
	}
	if _, err := os.Stat(owner.StateDir); !os.IsNotExist(err) {
		t.Fatal("cold construction initialized component recovery", err)
	}
}
func TestHEVColdConfiglessRemovalRetainsExactImageAndRefusesMixed(t *testing.T) {
	cfg, state, owner := hevColdFixture(t)
	hevColdWriteSidecar(t, state, "sing-box")
	if _, err := newColdDataplaneManager(context.Background(), state, nil, cfg, owner); err == nil {
		t.Fatal("ordinary cold observer guessed missing settings")
	}
	m, err := newColdRemovalDataplaneManager(context.Background(), state, nil, cfg, owner)
	if err != nil {
		t.Fatal(err)
	}
	hevColdAssertOwners(t, m, owner)
	// A second known standard sidecar is a conflicting previous lifetime, not
	// permission to reinterpret it as the currently inferred HEV global choice.
	standard := map[string]any{"log": map[string]any{"level": "warn", "timestamp": true}, "inbounds": []any{map[string]any{"type": "tun", "tag": "rz-tun-in", "interface_name": "rz-usque", "mtu": 1280, "auto_route": false, "strict_route": false, "stack": "gvisor", "inet4_address": []string{"172.31.20.1/30"}}}, "outbounds": []any{map[string]any{"type": "socks", "tag": "rz-socks-out", "server": "127.0.0.1", "server_port": 18080, "version": "5"}}, "route": map[string]any{"final": "rz-socks-out", "auto_detect_interface": true}}
	raw, _ := json.MarshalIndent(standard, "", "  ")
	path := filepath.Join(state, "usque", "runtime", "sidecar.json")
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := newColdRemovalDataplaneManager(context.Background(), state, nil, cfg, owner); err == nil {
		t.Fatal("mixed retained backend silently normalized")
	}
	got, _ := os.ReadFile(path)
	if string(got) != string(raw) {
		t.Fatal("mixed refusal rewrote original runtime")
	}
	if _, err := os.Stat(cfg); !os.IsNotExist(err) {
		t.Fatal("removal manufactured settings", err)
	}
}
func TestHEVColdRemovalRefusesOrphanOwnerAndMalformedRuntime(t *testing.T) {
	for _, bad := range []string{"pid-without-image", "foreign-image"} {
		t.Run(bad, func(t *testing.T) {
			cfg, state, owner := hevColdFixture(t)
			runtime := filepath.Join(state, "sing-box", "runtime")
			if err := os.MkdirAll(runtime, 0700); err != nil {
				t.Fatal(err)
			}
			name, data := "sidecar.pid", []byte("retained process owner")
			if bad == "foreign-image" {
				name, data = "sidecar.json", []byte(`{"socks5":{},"foreign":true}`)
			}
			if err := os.WriteFile(filepath.Join(runtime, name), data, 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := newColdRemovalDataplaneManager(context.Background(), state, nil, cfg, owner); err == nil {
				t.Fatal("unknown sidecar lifetime granted default fallback")
			}
		})
	}
}
