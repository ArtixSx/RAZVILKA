//go:build linux

package dataplane

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	xnetproxy "golang.org/x/net/proxy"

	"github.com/ArtixSx/razvilka/internal/engineconfig"
	"github.com/ArtixSx/razvilka/internal/nodestore"
)

// Opt-in only, coordinator-owned Ubuntu VM. These namespaces are fixtures;
// production requires no PID/network namespace facility. Real Xray server,
// Sing-box gVisor TUN, two LAN clients, TLS and kernel policy/iptables are used.
func TestNativeScopedXrayTUN(t *testing.T) {
	if os.Getenv("RAZVILKA_XRAY_TUN_NATIVE") != "1" {
		t.Skip("coordinator-only: opt-in scoped Xray TUN native fixture")
	}
	if role := os.Getenv("RAZVILKA_XRAY_TUN_ROLE"); role != "" {
		switch role {
		case "server":
			nativeScopedXrayServer(t)
		case "router":
			nativeScopedXrayRouter(t)
		case "probe":
			nativeScopedXrayProbe(t)
		default:
			t.Fatal("unknown scoped native role")
		}
		return
	}
	if os.Geteuid() != 0 {
		t.Fatal("requires root in the designated VM")
	}
	for _, name := range []string{"ip", "iptables", "ip6tables"} {
		if _, err := exec.LookPath(name); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"RAZVILKA_XRAY_NATIVE", "RAZVILKA_SINGBOX_NATIVE"} {
		if !filepath.IsAbs(os.Getenv(name)) {
			t.Fatal(name + " must name a pinned absolute executable")
		}
	}
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal("private scoped native fixture root", err)
	}
	nativeXrayCertificate(t, root)
	names := map[string]string{}
	for _, role := range []string{"router", "server", "selected", "control"} {
		ns := fmt.Sprintf("rz-xt-%s-%d", role, os.Getpid())
		nativeWGCommand(t, "", "ip", "netns", "add", ns)
		names[role] = ns
		t.Cleanup(func() {
			// A timed-out child can bypass testing cleanup. These namespaces were
			// successfully created exclusively by this test; reap only their PIDs.
			if output, err := exec.Command("ip", "netns", "pids", ns).Output(); err == nil {
				for _, pid := range strings.Fields(string(output)) {
					_ = exec.Command("kill", "-KILL", pid).Run()
				}
			} else {
				t.Errorf("read exact owned namespace PIDs: %v", err)
			}
			if out, err := exec.Command("ip", "netns", "delete", ns).CombinedOutput(); err != nil {
				t.Errorf("cleanup exact owned namespace: %v %s", err, out)
			}
		})
		nativeWGCommand(t, ns, "ip", "link", "set", "lo", "up")
	}
	router, server := names["router"], names["server"]
	nativeWGCommand(t, "", "ip", "link", "add", "wan-r", "netns", router, "type", "veth", "peer", "name", "wan-s", "netns", server)
	for _, link := range []struct{ ns, dev, addr string }{{router, "wan-r", "192.0.2.2/30"}, {server, "wan-s", "192.0.2.1/30"}} {
		nativeWGCommand(t, link.ns, "ip", "addr", "add", link.addr, "dev", link.dev)
		nativeWGCommand(t, link.ns, "ip", "link", "set", link.dev, "up")
	}
	nativeWGCommand(t, router, "ip", "link", "add", "br0", "type", "bridge")
	nativeWGCommand(t, router, "ip", "addr", "add", "192.168.1.1/24", "dev", "br0")
	nativeWGCommand(t, router, "ip", "link", "set", "br0", "up")
	for i, role := range []string{"selected", "control"} {
		port := fmt.Sprintf("lan-%d", i)
		nativeWGCommand(t, "", "ip", "link", "add", port, "netns", router, "type", "veth", "peer", "name", "client0", "netns", names[role])
		nativeWGCommand(t, router, "ip", "link", "set", port, "master", "br0")
		nativeWGCommand(t, router, "ip", "link", "set", port, "up")
		nativeWGCommand(t, names[role], "ip", "addr", "add", fmt.Sprintf("192.168.1.%d/24", 25+i), "dev", "client0")
		nativeWGCommand(t, names[role], "ip", "link", "set", "client0", "up")
		nativeWGCommand(t, names[role], "ip", "route", "add", "default", "via", "192.168.1.1")
	}
	for _, addr := range []string{"93.184.216.11/32", "93.184.216.12/32", "93.184.216.13/32", "93.184.216.14/32", "93.184.216.15/32"} {
		nativeWGCommand(t, server, "ip", "addr", "add", addr, "dev", "lo")
	}
	nativeWGCommand(t, router, "ip", "addr", "add", "93.184.216.16/32", "dev", "lo")
	nativeWGCommand(t, router, "ip", "route", "add", "default", "via", "192.0.2.1")
	nativeWGCommand(t, server, "ip", "route", "add", "192.168.1.0/24", "via", "192.0.2.2")
	nativeWGCommand(t, server, "ip", "route", "add", "93.184.216.16/32", "via", "192.0.2.2")
	nativeWGCommand(t, router, "sysctl", "-q", "-w", "net.ipv4.ip_forward=1")
	nativeWGCommand(t, router, "sysctl", "-q", "-w", "net.ipv4.conf.all.rp_filter=0")
	nativeWGCommand(t, router, "sysctl", "-q", "-w", "net.ipv4.conf.default.rp_filter=0")
	nativeWGCommand(t, router, "iptables", "-t", "nat", "-A", "POSTROUTING", "-s", "192.168.1.0/24", "-o", "wan-r", "-j", "SNAT", "--to-source", "93.184.216.16")
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	env := append(os.Environ(), "RAZVILKA_XRAY_TUN_ROOT="+root, "RAZVILKA_XRAY_TUN_SELECTED_NS="+names["selected"], "RAZVILKA_XRAY_TUN_CONTROL_NS="+names["control"])
	serverTimeout := 3*time.Minute + nativeScopedXrayFixtureExtraBudget()
	serverCmd := exec.Command("ip", "netns", "exec", server, exe, "-test.run=^TestNativeScopedXrayTUN$", "-test.v", "-test.timeout="+serverTimeout.String())
	serverCmd.Env = append(env, "RAZVILKA_XRAY_TUN_ROLE=server")
	serverCmd.Stdout, serverCmd.Stderr = os.Stdout, os.Stderr
	if err := serverCmd.Start(); err != nil {
		t.Fatal(err)
	}
	serverDone := make(chan error, 1)
	go func() { serverDone <- serverCmd.Wait() }()
	t.Cleanup(func() {
		if err := os.WriteFile(filepath.Join(root, "server.stop"), []byte("stop"), 0600); err != nil {
			t.Errorf("stop server fixture: %v", err)
		}
		select {
		case err := <-serverDone:
			if err != nil {
				t.Errorf("server fixture: %v", err)
			}
		case <-time.After(5 * time.Second):
			// Namespace PIDs are owned by this test. Reap the two server engines
			// before deleting the namespace even if the test child failed.
			if output, err := exec.Command("ip", "netns", "pids", server).Output(); err == nil {
				for _, pid := range strings.Fields(string(output)) {
					_ = exec.Command("kill", "-KILL", pid).Run()
				}
			}
			_ = serverCmd.Process.Kill()
			<-serverDone
			t.Error("server fixture did not finish graceful cleanup")
		}
	})
	deadline := time.Now().Add(10 * time.Second)
	for {
		if _, err := os.Stat(filepath.Join(root, "server.ready")); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("native server fixture did not start")
		}
		time.Sleep(50 * time.Millisecond)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Second+nativeScopedXrayFixtureExtraBudget())
	defer cancel()
	routerTimeout := 140*time.Second + nativeScopedXrayFixtureExtraBudget()
	cmd := exec.CommandContext(ctx, "ip", "netns", "exec", router, exe, "-test.run=^TestNativeScopedXrayTUN$", "-test.v", "-test.timeout="+routerTimeout.String())
	cmd.Env = append(env, "RAZVILKA_XRAY_TUN_ROLE=router")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("scoped TUN router scenario failed: %v\n%s", err, output)
	} else {
		t.Logf("%s", output)
	}
}

func nativeScopedXrayServer(t *testing.T) {
	root := os.Getenv("RAZVILKA_XRAY_TUN_ROOT")
	cert, key := filepath.Join(root, "ca.pem"), filepath.Join(root, "key.pem")
	nativeXrayListen(t, "93.184.216.12:443", cert, key, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host, _, _ := net.SplitHostPort(r.RemoteAddr)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"ip": host, "accepted": true})
	}))
	for i, addr := range []string{"93.184.216.11", "93.184.216.14"} {
		config := map[string]any{"log": map[string]any{"loglevel": "warning", "access": "none"}, "inbounds": []any{map[string]any{"listen": addr, "port": 443, "protocol": "vless", "settings": map[string]any{"clients": []any{map[string]any{"id": nativeXrayUUID}}, "decryption": "none"}, "streamSettings": map[string]any{"network": "tcp", "security": "tls", "tlsSettings": map[string]any{"certificates": []any{map[string]any{"certificateFile": cert, "keyFile": key}}}}}}, "outbounds": []any{map[string]any{"protocol": "freedom", "sendThrough": []string{"93.184.216.13", "93.184.216.15"}[i], "settings": map[string]any{}}}}
		path := filepath.Join(root, fmt.Sprintf("server-%d.json", i))
		data, _ := json.Marshal(config)
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
		clear(data)
		p := &nativeXrayProcess{t: t, binary: os.Getenv("RAZVILKA_XRAY_NATIVE"), config: path}
		p.start()
		t.Cleanup(p.stop)
		nativeXrayAwait(t, addr+":443")
	}
	if err := os.WriteFile(filepath.Join(root, "server.ready"), []byte("ready"), 0600); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(160*time.Second + nativeScopedXrayFixtureExtraBudget())
	for time.Now().Before(deadline) {
		if _, err := os.Stat(filepath.Join(root, "server.stop")); err == nil {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("server fixture stop was not received")
}

func nativeScopedXrayProbe(t *testing.T) {
	root := os.Getenv("RAZVILKA_XRAY_TUN_ROOT")
	raw, err := os.ReadFile(filepath.Join(root, "ca.pem"))
	if err != nil {
		t.Fatal(err)
	}
	ca := x509.NewCertPool()
	if !ca.AppendCertsFromPEM(raw) {
		t.Fatal("fixture CA")
	}
	destination := os.Getenv("RAZVILKA_XRAY_TUN_DESTINATION")
	transport := &http.Transport{Proxy: nil, DisableKeepAlives: true, TLSClientConfig: &tls.Config{RootCAs: ca, MinVersion: tls.VersionTLS13, ServerName: "service.example"}, DialContext: func(ctx context.Context, network, target string) (net.Conn, error) {
		return (&net.Dialer{Timeout: 4 * time.Second}).DialContext(ctx, "tcp4", net.JoinHostPort(destination, "443"))
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 7 * time.Second}
	response, err := client.Get("https://service.example/probe")
	if err != nil {
		t.Fatal("actual client HTTPS failed", err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 1025))
	if err != nil || len(body) > 1024 || response.StatusCode != 200 {
		t.Fatal("actual client service not accepted")
	}
	if err := os.WriteFile(os.Getenv("RAZVILKA_XRAY_TUN_PROBE_OUT"), body, 0600); err != nil {
		t.Fatal(err)
	}
}

func nativeScopedXrayRouter(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 130*time.Second+nativeScopedXrayFixtureExtraBudget())
	defer cancel()
	root := os.Getenv("RAZVILKA_XRAY_TUN_ROOT")
	t.Setenv("SSL_CERT_FILE", filepath.Join(root, "ca.pem"))
	t.Setenv("SSL_CERT_DIR", filepath.Join(root, "empty-roots"))
	state := filepath.Join(root, "router-state")
	nodesRoot := filepath.Join(root, "nodes")
	if err := os.Mkdir(nodesRoot, 0700); err != nil {
		t.Fatal(err)
	}
	store, err := nodestore.Open(nodesRoot)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	now := time.Now().UTC()
	snap, err := store.Import(ctx, nodestore.Source{ID: "manual", Kind: "manual"}, "vless://"+nativeXrayUUID+"@node.example:443?security=tls&sni=front.example", now, time.Hour, false)
	if err != nil {
		t.Fatal(err)
	}
	id := snap.Nodes[0].ID
	// Bootstrap only the private materializer boundary. Native path acceptance
	// below comes exclusively from real selected/control traffic + live receipts.
	_, err = store.RecordCheck(ctx, id, nodestore.CheckRecord{ProbeID: "native-tun-admission", ServiceID: "native-site", NetworkProfile: executionNetwork, RoutePathID: "xray:" + id, TestLevel: "service", Stage: "service", Verdict: "PASS", State: "available", CheckedAt: now, ExpiresAt: now.Add(time.Hour)}, now)
	if err != nil {
		t.Fatal(err)
	}
	profile := executionNetwork
	endpoint := "93.184.216.11"
	expectedExit := "93.184.216.13"
	caRaw, err := os.ReadFile(filepath.Join(root, "ca.pem"))
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	_ = roots.AppendCertsFromPEM(caRaw)
	probeSOCKS := func(ctx context.Context, rawURL, address string, pinned netip.Addr) error {
		return nativeScopedSOCKSService(ctx, rawURL, address, pinned, roots)
	}
	var lastSelected netip.Addr
	newAdapter := func() *ProxyTunnelAdapter {
		a, err := NewScopedXrayTunnelAdapter(engineconfig.New(filepath.Join(root, "drafts"), filepath.Join(root, "backups")), state, func(ctx context.Context, req []NodeRouteRequest, p string, at time.Time) (NodeRouteMaterial, error) {
			var bindings []nodestore.RouteBinding
			for _, r := range req {
				bindings = append(bindings, nodestore.RouteBinding{ServiceID: r.ServiceID, NodeID: r.NodeID, NetworkProfile: p, Domains: r.Domains, Destinations: r.Destinations})
			}
			m, e := store.MaterializeXray(ctx, bindings, at)
			return NodeRouteMaterial{EngineID: m.EngineID, Config: m.Config, EndpointHosts: m.EndpointHosts}, e
		})
		if err != nil {
			t.Fatal(err)
		}
		a.EngineBin, a.SidecarBin, a.IP, a.IPTables, a.IP6Tables = os.Getenv("RAZVILKA_XRAY_NATIVE"), os.Getenv("RAZVILKA_SINGBOX_NATIVE"), "ip", "iptables", "ip6tables"
		a.Timeout = 8 * time.Second
		a.FreshProfile = func(context.Context) (string, error) { return profile, nil }
		a.Resolver = func(_ context.Context, host string) ([]netip.Addr, error) {
			if host == "node.example" {
				return []netip.Addr{netip.MustParseAddr(endpoint), netip.MustParseAddr("93.184.216.11")}, nil
			}
			return []netip.Addr{netip.MustParseAddr("93.184.216.12")}, nil
		}
		a.CanaryProbe = func(ctx context.Context, url, address string) error {
			return probeSOCKS(ctx, url, address, netip.MustParseAddr("93.184.216.12"))
		}
		a.ServiceIPProbe = probeSOCKS
		a.NodeTUNProbe = func(ctx context.Context, r NodeTUNRequest) (NodeTUNObservation, error) {
			observation := NodeTUNObservation{RuntimeID: r.RuntimeID, SelectedSource: netip.MustParseAddr("192.168.1.25"), ControlSource: netip.MustParseAddr("192.168.1.26")}
			for i, role := range []string{"SELECTED", "CONTROL"} {
				exe, _ := os.Executable()
				out := filepath.Join(root, "probe-"+strings.ToLower(role)+".json")
				_ = os.Remove(out)
				cmd := exec.CommandContext(ctx, "ip", "netns", "exec", os.Getenv("RAZVILKA_XRAY_TUN_"+role+"_NS"), exe, "-test.run=^TestNativeScopedXrayTUN$", "-test.timeout=10s")
				cmd.Env = append(os.Environ(), "RAZVILKA_XRAY_TUN_ROLE=probe", "RAZVILKA_XRAY_TUN_DESTINATION="+r.Destination.String(), "RAZVILKA_XRAY_TUN_PROBE_OUT="+out)
				if output, err := cmd.CombinedOutput(); err != nil {
					return observation, fmt.Errorf("actual %s client probe failed: %v %s", role, err, output)
				}
				data, err := os.ReadFile(out)
				var result struct {
					IP       string `json:"ip"`
					Accepted bool   `json:"accepted"`
				}
				if err != nil || json.Unmarshal(data, &result) != nil || !result.Accepted {
					return observation, errors.New("native service response missing")
				}
				address, err := netip.ParseAddr(result.IP)
				if err != nil {
					return observation, err
				}
				if i == 0 {
					observation.SelectedEgress = address
					lastSelected = address
				} else {
					observation.ControlEgress = address
				}
			}
			observation.ServiceAccepted = true
			return observation, nil
		}
		return a
	}
	a := newAdapter()
	var routerHTTPSLease *nativeRouterHTTPSLease
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if routerHTTPSLease != nil {
			if err := routerHTTPSLease.assertAbsent(cleanup); err != nil {
				t.Errorf("router HTTPS lease must be absent before Deactivate: %v", err)
				return
			}
		}
		if err := a.Deactivate(cleanup); err != nil {
			t.Errorf("owned adapter cleanup: %v", err)
		}
	})
	plan := Plan{NetworkProfileID: profile, Routes: []Route{{ServiceID: "native-site", ServiceName: "Native site", Selected: "xray:" + id, Resolved: "xray:" + id, Domains: []string{"service.example"}, Sources: []string{"192.168.1.25/32"}, ProbeURL: "https://service.example/probe"}}}
	stage := func(label string) string {
		transaction := filepath.Join(root, label)
		for _, step := range []func(context.Context, Plan, string) error{a.Snapshot, a.Stage, a.Validate} {
			if err := step(ctx, plan, transaction); err != nil {
				t.Fatal(label, err)
			}
		}
		if err := a.Canary(ctx, plan.RoutePlanFor("xray"), transaction); err != nil {
			t.Fatal(label, "canary", err)
		}
		return transaction
	}
	assertHealth := func(label string) {
		if err := a.CommittedNodeHealth(ctx, plan); err != nil {
			t.Fatal(label, err)
		}
		if lastSelected.String() != expectedExit {
			t.Fatal(label, "wrong exit", lastSelected)
		}
		t.Log(label + ": real selected TUN exit differs from same-destination control")
	}
	first := stage("A")
	for _, step := range []func(context.Context, Plan, string) error{a.Activate, a.Health, a.Commit} {
		if err := step(ctx, plan, first); err != nil {
			t.Fatal(err)
		}
	}
	assertHealth("A active")
	if os.Getenv("RAZVILKA_NODE_TRANSIT_MANAGER_NATIVE") == "1" {
		if err := nativeScopedXrayManagerTransit(t, ctx, a, plan, roots, expectedExit); err != nil {
			t.Fatal("actual Manager node transit", err)
		}
	}
	if os.Getenv("RAZVILKA_XRAY_ROUTER_HTTPS_NATIVE") == "1" {
		routerHTTPSLease, err = nativeScopedXrayRouterHTTPS(t, ctx, a, plan, roots, expectedExit)
		if err != nil {
			t.Fatal("actual router TUN HTTPS component", err)
		}
	}
	// Read current on-disk state in a new adapter; no candidate identity is used.
	a = newAdapter()
	assertHealth("fresh adapter runtime inspection")
	pid, err := readManagedPID(a.sidecarProcess())
	if err != nil {
		t.Fatal(err)
	}
	process, _ := os.FindProcess(pid)
	_ = process.Kill()
	deadline := time.Now().Add(3 * time.Second)
	for a.Processes.Running(a.sidecarProcess()) && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if err := a.CommittedNodeHealth(ctx, plan); err == nil {
		t.Fatal("killed sidecar retained health")
	}
	if err := a.Reconcile(ctx, plan); err != nil {
		t.Fatal("sidecar reconcile", err)
	}
	assertHealth("sidecar kill/restart")
	endpoint = "93.184.216.14"
	second := stage("B")
	if err := a.Activate(ctx, plan, second); err != nil {
		t.Fatal(err)
	}
	expectedExit = "93.184.216.15"
	if err := a.Health(ctx, plan, second); err != nil {
		t.Fatal(err)
	}
	if lastSelected.String() != expectedExit {
		t.Fatal("endpoint replacement did not change actual exit")
	}
	// B's real sidecar dies after its successful health probe. The unchanged
	// owned config/lease remains cleanup authority; absent runtime cannot commit.
	pid, err = readManagedPID(a.sidecarProcess())
	if err != nil {
		t.Fatal(err)
	}
	process, _ = os.FindProcess(pid)
	_ = process.Kill()
	deadline = time.Now().Add(3 * time.Second)
	for a.Processes.Running(a.sidecarProcess()) && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if err := a.Commit(ctx, plan, second); err == nil {
		t.Fatal("dead B sidecar committed")
	}
	if err := a.Rollback(ctx, plan, second); err != nil {
		t.Fatal("rollback A", err)
	}
	if ok, err := a.VerifyRollback(ctx, plan, second); err != nil || !ok {
		t.Fatal("rollback not verified", ok, err)
	}
	expectedExit = "93.184.216.13"
	assertHealth("B failure -> verified A rollback")
	t.Log("native scoped Xray TUN lifecycle complete; no Internet/router/HIL or production Selectable claim")
}

func nativeScopedSOCKSService(ctx context.Context, rawURL, address string, pinned netip.Addr, roots *x509.CertPool) error {
	dialer, err := xnetproxy.SOCKS5("tcp", address, nil, &net.Dialer{Timeout: 3 * time.Second})
	if err != nil {
		return err
	}
	transport := &http.Transport{Proxy: nil, DisableKeepAlives: true, TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13, ServerName: "service.example"}, DialContext: func(ctx context.Context, network, target string) (net.Conn, error) {
		return dialer.(xnetproxy.ContextDialer).DialContext(ctx, "tcp4", net.JoinHostPort(pinned.String(), "443"))
	}}
	defer transport.CloseIdleConnections()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return err
	}
	response, err := (&http.Client{Transport: transport, Timeout: 5 * time.Second}).Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		return errors.New("native service not accepted")
	}
	_, err = io.Copy(io.Discard, io.LimitReader(response.Body, 1024))
	return err
}
