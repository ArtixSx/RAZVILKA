package dataplane

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ArtixSx/razvilka/internal/engineconfig"
)

type proxyFakeProcesses struct {
	running    map[string]bool
	startSpecs []ProcessSpec
}

func (p *proxyFakeProcesses) Start(_ context.Context, spec ProcessSpec) error {
	if p.running == nil {
		p.running = map[string]bool{}
	}
	p.running[spec.ID] = true
	p.startSpecs = append(p.startSpecs, spec)
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

func TestUsqueUsesUpstreamMASQUEDefaultAndReconnect(t *testing.T) {
	adapter, err := NewProxyTunnelAdapter("usque", engineconfig.New(t.TempDir(), t.TempDir()), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	adapter.EngineBin = "usque"
	args := strings.Join(adapter.engineProcess().Args, " ")
	for _, required := range []string{"socks", "-b 127.0.0.1", "-p 18080", "--always-reconnect", "-S"} {
		if !strings.Contains(args, required) {
			t.Fatalf("usque command %q is missing %q", args, required)
		}
	}
	if strings.Contains(args, "--http2") {
		t.Fatalf("usque command %q must not force the HTTP/2 fallback", args)
	}
}

func TestParseUsqueTransportAcceptsOnlySafePackageSettings(t *testing.T) {
	got := parseUsqueTransport("SNI=\"ozon.ru\"\nHTTP2_ENABLE=1\n")
	if got.SNI != "ozon.ru" || !got.HTTP2 {
		t.Fatalf("transport=%+v", got)
	}
	got = parseUsqueTransport("SNI='bad value; reboot'\nHTTP2_ENABLE=0\n")
	if got.SNI != "" || got.HTTP2 {
		t.Fatalf("unsafe transport setting was accepted: %+v", got)
	}
}

func TestUsqueCanaryFallsBackToHTTP2AndPersistsSelection(t *testing.T) {
	root := t.TempDir()
	adapter, err := NewProxyTunnelAdapter("usque", engineconfig.New(filepath.Join(root, "stage"), filepath.Join(root, "backups")), filepath.Join(root, "state"))
	if err != nil {
		t.Fatal(err)
	}
	adapter.EngineBin = "usque"
	adapter.UsqueConfig = filepath.Join(root, "usque.conf")
	if err := os.WriteFile(adapter.UsqueConfig, []byte("SNI=\"ozon.ru\"\nHTTP2_ENABLE=0\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	processes := &proxyFakeProcesses{running: map[string]bool{}}
	adapter.Processes = processes
	adapter.SOCKSProbe = func(context.Context, string) error { return nil }
	probeCount := 0
	adapter.CanaryProbe = func(context.Context, string, string) error {
		probeCount++
		if probeCount == 1 {
			return errors.New("QUIC tunnel stalled")
		}
		return nil
	}
	transaction := filepath.Join(root, "transaction")
	if err := os.MkdirAll(transaction, 0o700); err != nil {
		t.Fatal(err)
	}
	config := `{"private_key":"key","endpoint_pub_key":"pub","id":"device","access_token":"token"}`
	if err := os.WriteFile(filepath.Join(transaction, "engine.staged.json"), []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	plan := RoutePlan{Routes: []Route{{ServiceName: "Telegram", ProbeURL: "https://telegram.org/"}}}
	if err := adapter.Canary(context.Background(), plan, transaction); err != nil {
		t.Fatal(err)
	}
	if probeCount != 2 || len(processes.startSpecs) != 2 {
		t.Fatalf("probes=%d starts=%d", probeCount, len(processes.startSpecs))
	}
	firstArgs := strings.Join(processes.startSpecs[0].Args, " ")
	secondArgs := strings.Join(processes.startSpecs[1].Args, " ")
	if strings.Contains(firstArgs, "--http2") || !strings.Contains(firstArgs, "-s ozon.ru") {
		t.Fatalf("unexpected QUIC args: %s", firstArgs)
	}
	if !strings.Contains(secondArgs, "--http2") || !strings.Contains(secondArgs, "-s ozon.ru") {
		t.Fatalf("unexpected HTTP/2 args: %s", secondArgs)
	}
	selected, err := adapter.stagedUsqueTransport(transaction)
	if err != nil || !selected.HTTP2 || selected.SNI != "ozon.ru" {
		t.Fatalf("selected=%+v err=%v", selected, err)
	}
	if len(processes.running) != 0 {
		t.Fatalf("canary process remained: %v", processes.running)
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
	canaryProbes := 0
	adapter.CanaryProbe = func(_ context.Context, rawURL, address string) error {
		canaryProbes++
		if !strings.HasSuffix(address, ":19081") {
			t.Fatalf("unexpected canary address %q", address)
		}
		if rawURL != "https://example.com" {
			t.Fatalf("unexpected canary probe URL %q", rawURL)
		}
		return nil
	}
	transaction := filepath.Join(root, "transaction")
	plan := Plan{EngineDrafts: []string{"sing-box/main"}, Routes: []Route{{ServiceName: "Example", Resolved: "sing-box", Domains: []string{"example.com"}, Sources: []string{"192.168.1.25/32"}, ProbeURL: "https://example.com"}}}
	if err := adapter.Snapshot(context.Background(), plan, transaction); err != nil {
		t.Fatal(err)
	}
	if err := adapter.Stage(context.Background(), plan, transaction); err != nil {
		t.Fatal(err)
	}
	if err := adapter.Validate(context.Background(), plan, transaction); err != nil {
		t.Fatal(err)
	}
	if err := adapter.Canary(context.Background(), Plan{Routes: plan.Routes}.RoutePlanFor("sing-box"), transaction); err != nil {
		t.Fatal(err)
	}
	if canaryProbes != 1 {
		t.Fatalf("canary probes=%d want=1", canaryProbes)
	}
	if len(processes.running) != 0 {
		t.Fatalf("canary process remained before activation: %v", processes.running)
	}
	if regularFile(adapter.engineConfigPath()) || regularFile(adapter.sidecarConfigPath()) || regularFile(adapter.policyPath()) {
		t.Fatal("canary wrote live runtime state before activation")
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

func TestProxyCanaryFailureCleansCandidateAndLeavesRuntimeUntouched(t *testing.T) {
	root := t.TempDir()
	configs := engineconfig.New(filepath.Join(root, "stage"), filepath.Join(root, "backups"))
	if _, err := configs.Stage("sing-box", "main", `{"outbounds":[{"type":"vless","server":"node.example","server_port":443}]}`); err != nil {
		t.Fatal(err)
	}
	adapter, err := NewProxyTunnelAdapter("sing-box", configs, filepath.Join(root, "state"))
	if err != nil {
		t.Fatal(err)
	}
	processes := &proxyFakeProcesses{running: map[string]bool{"sing-box-engine": true, "sing-box-tun": true}}
	adapter.Processes = processes
	adapter.Runner = &proxyFakeRunner{processes: processes, iface: adapter.Interface}
	adapter.EngineBin, adapter.SidecarBin, adapter.IP = "sing-box", "sing-box", "ip"
	adapter.Resolver = func(_ context.Context, host string) ([]netip.Addr, error) {
		if host == "node.example" {
			return []netip.Addr{netip.MustParseAddr("203.0.113.9")}, nil
		}
		return []netip.Addr{netip.MustParseAddr("198.51.100.20")}, nil
	}
	adapter.SOCKSProbe = func(context.Context, string) error { return nil }
	adapter.CanaryProbe = func(context.Context, string, string) error { return fmt.Errorf("forced service failure") }
	transaction := filepath.Join(root, "transaction")
	plan := Plan{EngineDrafts: []string{"sing-box/main"}, Routes: []Route{{ServiceID: "telegram", ServiceName: "Telegram", Resolved: "sing-box", Domains: []string{"telegram.org"}, ProbeURL: "https://telegram.org/"}}}
	if err := adapter.Snapshot(context.Background(), plan, transaction); err != nil {
		t.Fatal(err)
	}
	if err := adapter.Stage(context.Background(), plan, transaction); err != nil {
		t.Fatal(err)
	}
	if err := adapter.Validate(context.Background(), plan, transaction); err != nil {
		t.Fatal(err)
	}
	err = adapter.Canary(context.Background(), plan.RoutePlanFor("sing-box"), transaction)
	if err == nil || !strings.Contains(err.Error(), "candidate probe") {
		t.Fatalf("unexpected canary result: %v", err)
	}
	if !processes.running["sing-box-engine"] || !processes.running["sing-box-tun"] || len(processes.running) != 2 {
		t.Fatalf("failed canary changed live processes: %v", processes.running)
	}
	if regularFile(adapter.engineConfigPath()) || regularFile(adapter.sidecarConfigPath()) || regularFile(adapter.policyPath()) {
		t.Fatal("failed canary changed live runtime state")
	}
}

func TestProxySnapshotIgnoresEngineDraftOutsideTransactionScope(t *testing.T) {
	root := t.TempDir()
	configs := engineconfig.New(filepath.Join(root, "stage"), filepath.Join(root, "backups"))
	if _, err := configs.Stage("sing-box", "main", `{"outbounds":[{"type":"vless","server":"draft.example","server_port":443}]}`); err != nil {
		t.Fatal(err)
	}
	adapter, err := NewProxyTunnelAdapter("sing-box", configs, filepath.Join(root, "state"))
	if err != nil {
		t.Fatal(err)
	}
	transaction := filepath.Join(root, "transaction")
	if err := adapter.Snapshot(context.Background(), Plan{}, transaction); err != nil {
		t.Fatal(err)
	}
	snapshot, err := readProxySnapshot(transaction)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.ConfigDraft || len(snapshot.StagedConfig) != 0 {
		t.Fatal("unscoped engine draft received transaction authority")
	}
	if err := adapter.Stage(context.Background(), Plan{}, transaction); err == nil || !strings.Contains(err.Error(), "configuration is empty") {
		t.Fatalf("unscoped draft was unexpectedly staged: %v", err)
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
