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

	"github.com/ArtixSx/razvilka/internal/engineconfig"
)

type proxyFakeProcesses struct {
	running map[string]bool
}

func (p *proxyFakeProcesses) Start(_ context.Context, spec ProcessSpec) error {
	if p.running == nil {
		p.running = map[string]bool{}
	}
	p.running[spec.ID] = true
	return nil
}
func (p *proxyFakeProcesses) Stop(_ context.Context, spec ProcessSpec) error {
	delete(p.running, spec.ID)
	return nil
}
func (p *proxyFakeProcesses) Running(spec ProcessSpec) bool { return p.running[spec.ID] }

type proxyFakeRunner struct {
	processes      *proxyFakeProcesses
	iface          string
	packageRunning bool
	packageCalls   []string
}

func (r *proxyFakeRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	joined := strings.Join(args, " ")
	if name == "/opt/etc/init.d/S51usque" {
		r.packageCalls = append(r.packageCalls, joined)
		switch joined {
		case "status":
			if r.packageRunning {
				return []byte("Service USQUE is running (PID 123)"), nil
			}
			return []byte("Service USQUE is stopped"), nil
		case "stop":
			r.packageRunning = false
			return []byte("stopped"), nil
		case "start":
			r.packageRunning = true
			return []byte("started"), nil
		}
	}
	if name == "sing-box" && joined == "version" {
		return []byte("sing-box version 1.14.0"), nil
	}
	if name == "ip" && strings.HasPrefix(joined, "link show dev ") {
		if r.processes.running["sing-box-tun"] {
			return []byte(r.iface + ": UP"), nil
		}
		return nil, fmt.Errorf("device not found")
	}
	if name == "ip" && strings.Contains(joined, "route get") {
		return []byte("198.51.100.20 dev " + r.iface), nil
	}
	return []byte("ok"), nil
}

func TestUsqueUsesHTTP2FallbackAndReconnect(t *testing.T) {
	adapter, err := NewProxyTunnelAdapter("usque", engineconfig.New(t.TempDir(), t.TempDir()), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	adapter.EngineBin = "usque"
	args := strings.Join(adapter.engineProcess().Args, " ")
	for _, required := range []string{"socks", "-b 127.0.0.1", "-p 18080", "--http2", "--always-reconnect", "-S"} {
		if !strings.Contains(args, required) {
			t.Fatalf("usque command %q is missing %q", args, required)
		}
	}
}

func TestUsquePackageRuntimeCanBeSuspendedAndRestored(t *testing.T) {
	adapter, err := NewProxyTunnelAdapter("usque", engineconfig.New(t.TempDir(), t.TempDir()), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	runner := &proxyFakeRunner{packageRunning: true}
	adapter.Runner = runner
	adapter.PackageInit = "/opt/etc/init.d/S51usque"
	if err := adapter.stopPackageRuntime(context.Background()); err != nil {
		t.Fatal(err)
	}
	if runner.packageRunning {
		t.Fatal("package runtime was not stopped")
	}
	if err := adapter.startPackageRuntime(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !runner.packageRunning {
		t.Fatal("package runtime was not restored")
	}
	want := []string{"status", "stop", "start"}
	if strings.Join(runner.packageCalls, ",") != strings.Join(want, ",") {
		t.Fatalf("calls=%v want=%v", runner.packageCalls, want)
	}
}

func TestBuildProxyCandidateReplacesListeners(t *testing.T) {
	source := []byte(`{"inbounds":[{"type":"mixed","listen":"0.0.0.0","listen_port":1080}],"outbounds":[{"type":"vless","server":"node.example","server_port":443}],"experimental":{"clash_api":{"external_controller":"0.0.0.0:9090"}}}`)
	data, endpoints, err := buildProxyCandidate("sing-box", source, 18081)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	if strings.Contains(text, "0.0.0.0") || strings.Contains(text, "experimental") || !strings.Contains(text, `"listen": "127.0.0.1"`) || !strings.Contains(text, `"listen_port": 18081`) {
		t.Fatalf("candidate was not isolated: %s", text)
	}
	if len(endpoints) != 1 || endpoints[0] != "node.example" {
		t.Fatalf("endpoints=%v", endpoints)
	}
}

func TestBuildSOCKSTunnelNeverOwnsDefaultRoute(t *testing.T) {
	data, err := buildSOCKSTunnelConfig("rz-test", "172.31.29.1/30", 18090)
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := json.Unmarshal(data, &document); err != nil {
		t.Fatal(err)
	}
	inbound := document["inbounds"].([]any)[0].(map[string]any)
	if inbound["auto_route"] != false || inbound["interface_name"] != "rz-test" {
		t.Fatalf("unsafe TUN config: %s", data)
	}
}

func TestBuildSOCKSTunnelDisablesNewSingBoxDNSOwnership(t *testing.T) {
	data, err := buildSOCKSTunnelConfigForSchema("rz-test", "172.31.29.1/30", 18090, singBoxSidecarSchema{modernAddress: true, dnsMode: true})
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := json.Unmarshal(data, &document); err != nil {
		t.Fatal(err)
	}
	inbound := document["inbounds"].([]any)[0].(map[string]any)
	if inbound["dns_mode"] != "disabled" || inbound["auto_route"] != false {
		t.Fatalf("sidecar attempted to own DNS or default routes: %s", data)
	}
}

func TestRejectEndpointOverlapCatchesBroadCIDR(t *testing.T) {
	err := rejectEndpointOverlap(context.Background(), []string{"203.0.113.0/24"}, []string{"node.example"}, func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("203.0.113.9")}, nil
	})
	if err == nil || !strings.Contains(err.Error(), "self-tunnel") {
		t.Fatalf("overlap was accepted: %v", err)
	}
}

func TestProxyAdapterStagesActivatesHealthAndRollsBack(t *testing.T) {
	root := t.TempDir()
	configs := engineconfig.New(filepath.Join(root, "stage"), filepath.Join(root, "backups"))
	source := `{"inbounds":[{"type":"mixed","listen":"0.0.0.0","listen_port":1080}],"outbounds":[{"type":"vless","server":"node.example","server_port":443}]}`
	if _, err := configs.Stage("sing-box", "main", source); err != nil {
		t.Fatal(err)
	}
	adapter, err := NewProxyTunnelAdapter("sing-box", configs, filepath.Join(root, "state"))
	if err != nil {
		t.Fatal(err)
	}
	processes := &proxyFakeProcesses{running: map[string]bool{}}
	runner := &proxyFakeRunner{processes: processes, iface: adapter.Interface}
	adapter.Processes, adapter.Runner = processes, runner
	adapter.EngineBin, adapter.SidecarBin, adapter.IP = "sing-box", "sing-box", "ip"
	adapter.Resolver = func(_ context.Context, host string) ([]netip.Addr, error) {
		if host == "node.example" {
			return []netip.Addr{netip.MustParseAddr("203.0.113.9")}, nil
		}
		return []netip.Addr{netip.MustParseAddr("198.51.100.20")}, nil
	}
	adapter.SOCKSProbe = func(context.Context, string) error { return nil }
	adapter.Probe = func(context.Context, string) error { return nil }
	transaction := filepath.Join(root, "transaction")
	plan := Plan{Routes: []Route{{ServiceName: "Example", Resolved: "sing-box", Domains: []string{"example.com"}, ProbeURL: "https://example.com"}}}
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
	if !processes.running["sing-box-engine"] || !processes.running["sing-box-tun"] {
		t.Fatal("managed engine pair was not activated")
	}
	if err := adapter.Rollback(context.Background(), plan, transaction); err != nil {
		t.Fatal(err)
	}
	if len(processes.running) != 0 {
		t.Fatalf("managed processes remained after rollback: %v", processes.running)
	}
	content, err := configs.ReadExpert("sing-box", "main")
	if err != nil || content.Source != "staged" {
		t.Fatalf("draft was not preserved: %+v err=%v", content, err)
	}
}

func TestProxyDeactivateRemovesOwnedRuntime(t *testing.T) {
	root := t.TempDir()
	configs := engineconfig.New(filepath.Join(root, "stage"), filepath.Join(root, "backups"))
	adapter, err := NewProxyTunnelAdapter("sing-box", configs, filepath.Join(root, "state"))
	if err != nil {
		t.Fatal(err)
	}
	processes := &proxyFakeProcesses{running: map[string]bool{"sing-box-engine": true, "sing-box-tun": true}}
	adapter.Processes = processes
	adapter.Runner = &proxyFakeRunner{processes: processes, iface: adapter.Interface}
	adapter.EngineBin, adapter.SidecarBin, adapter.IP = "sing-box", "sing-box", "ip"
	if err := os.MkdirAll(adapter.runtimeRoot(), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(adapter.engineConfigPath(), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(adapter.sidecarConfigPath(), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	policy := PolicyState{Interface: adapter.Interface, Table: adapter.Table, PriorityBase: adapter.Priority, Prefixes: []string{"198.51.100.20/32"}}
	data, _ := json.Marshal(policy)
	if err := os.MkdirAll(adapter.StateRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(adapter.policyPath(), data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := adapter.Deactivate(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(processes.running) != 0 {
		t.Fatalf("owned processes remain: %v", processes.running)
	}
	for _, path := range []string{adapter.policyPath(), adapter.engineConfigPath(), adapter.sidecarConfigPath()} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("owned runtime file remains: %s", path)
		}
	}
}
