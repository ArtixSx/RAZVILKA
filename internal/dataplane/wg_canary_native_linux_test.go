//go:build linux

package dataplane

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Opt-in kernel integration: run only in an exclusively assigned Linux VM.
// No external host, router, account or shared listener is used. Each namespace
// is created by this test, and only successfully created namespaces are removed.
func TestWGNativeCandidateIsolation(t *testing.T) {
	nativeWGFixture(t, "TestWGNativeCandidateIsolation")
}

func TestWGNativeEndpointLifecycle(t *testing.T) {
	if os.Getenv("RAZVILKA_WG_NATIVE_ROLE") != "" {
		nativeWGFixture(t, "TestWGNativeEndpointLifecycle")
		return
	}
	// A failure (including t.Fatal in a child) must not leave the next family
	// sharing kernel state. Each case owns a complete independent topology.
	for _, endpoint := range []string{"93.184.216.34", "2606:4700::1111"} {
		t.Run(endpoint, func(t *testing.T) { nativeWGFixture(t, "TestWGNativeEndpointLifecycle", endpoint) })
	}
}

func nativeWGFixture(t *testing.T, suite string, selectedEndpoint ...string) {
	if os.Getenv("RAZVILKA_WG_NATIVE") != "1" {
		t.Skip("requires exclusive Linux VM: RAZVILKA_WG_NATIVE=1 go test ./internal/dataplane -run '^" + suite + "$' -count=1 -v")
	}
	if role := os.Getenv("RAZVILKA_WG_NATIVE_ROLE"); role != "" {
		if role == "server" {
			nativeWGServe(t)
		} else if role == "recover" && suite == "TestWGNativeEndpointLifecycle" {
			nativeWGEndpointRecover(t)
		} else if role == "client" && suite == "TestWGNativeEndpointLifecycle" {
			nativeWGEndpointClient(t)
		} else if role == "client" {
			nativeWGClient(t)
		} else {
			t.Fatal("unexpected native fixture role")
		}
		return
	}
	if os.Geteuid() != 0 {
		t.Fatal("native WireGuard harness requires root in the dedicated VM")
	}
	for _, name := range []string{"ip", "wg"} {
		if _, err := exec.LookPath(name); err != nil {
			t.Fatal(err)
		}
	}
	root := t.TempDir()
	clientNS, serverNS := fmt.Sprintf("rz-wg-c-%d", os.Getpid()), fmt.Sprintf("rz-wg-s-%d", os.Getpid())
	run := func(args ...string) string { return nativeWGCommand(t, "", args...) }
	for _, ns := range []string{clientNS, serverNS} {
		run("ip", "netns", "add", ns)
		t.Cleanup(func() {
			if out, err := exec.Command("ip", "netns", "delete", ns).CombinedOutput(); err != nil {
				t.Errorf("cleanup owned namespace %s: %s %v", ns, out, err)
			}
		})
		nativeWGCommand(t, ns, "ip", "link", "set", "lo", "up")
	}
	run("ip", "link", "add", "wan-c", "netns", clientNS, "type", "veth", "peer", "name", "wan-s", "netns", serverNS)
	for _, link := range []struct{ ns, dev, addr string }{{clientNS, "wan-c", "192.0.2.2/30"}, {serverNS, "wan-s", "192.0.2.1/30"}} {
		nativeWGCommand(t, link.ns, "ip", "address", "add", link.addr, "dev", link.dev)
		nativeWGCommand(t, link.ns, "ip", "link", "set", link.dev, "up")
	}
	if suite == "TestWGNativeEndpointLifecycle" {
		for _, link := range []struct{ ns, dev, addr string }{{clientNS, "wan-c", "2001:db8:1::2/64"}, {serverNS, "wan-s", "2001:db8:1::1/64"}} {
			nativeWGCommand(t, link.ns, "ip", "address", "add", link.addr, "dev", link.dev, "nodad")
		}
		for _, addr := range []string{"93.184.216.34/32", "2606:4700::1111/128"} {
			nativeWGCommand(t, serverNS, "ip", "address", "add", addr, "dev", "lo", "nodad")
		}
		nativeWGCommand(t, clientNS, "ip", "route", "add", "93.184.216.34/32", "via", "192.0.2.1", "dev", "wan-c")
		nativeWGCommand(t, clientNS, "ip", "-6", "route", "add", "2606:4700::1111/128", "via", "2001:db8:1::1", "dev", "wan-c")
	}
	serverPrivate, serverPublic := nativeWGKeys(t)
	clientPrivate, clientPublic := nativeWGKeys(t)
	candidatePrivate, candidatePublic := nativeWGKeys(t)
	serverConfig := "[Interface]\nPrivateKey = " + serverPrivate + "\nListenPort = 51820\n[Peer]\nPublicKey = " + clientPublic + "\nAllowedIPs = 10.66.0.2/32, 2001:db8:66::2/128\n"
	serverPath := filepath.Join(root, "server.conf")
	if err := os.WriteFile(serverPath, []byte(serverConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	nativeWGCommand(t, serverNS, "ip", "link", "add", "wg-server", "type", "wireguard")
	nativeWGCommand(t, serverNS, "wg", "setconf", "wg-server", serverPath)
	nativeWGCommand(t, serverNS, "ip", "link", "set", "wg-server", "up")
	for _, value := range []string{"198.51.100.10/32", "2001:db8:10::10/128"} {
		nativeWGCommand(t, serverNS, "ip", "address", "add", value, "dev", "lo", "nodad")
	}
	nativeWGCommand(t, serverNS, "ip", "route", "add", "10.66.0.2/32", "dev", "wg-server")
	nativeWGCommand(t, serverNS, "ip", "-6", "route", "add", "2001:db8:66::2/128", "dev", "wg-server")
	profile := "[Interface]\nPrivateKey = " + clientPrivate + "\nAddress = 10.66.0.2/32, 2001:db8:66::2/128\n[Peer]\nPublicKey = " + serverPublic + "\nEndpoint = 192.0.2.1:51820\nAllowedIPs = 0.0.0.0/0, ::/0\n"
	if err := os.WriteFile(filepath.Join(root, "client.conf"), []byte(profile), 0o600); err != nil {
		t.Fatal(err)
	}
	// Independent peer state for successful same-Address probes. The same-key
	// production rejection is tested separately below against the original peer.
	candidateNS := fmt.Sprintf("rz-wg-b-%d", os.Getpid())
	run("ip", "netns", "add", candidateNS)
	t.Cleanup(func() {
		if out, err := exec.Command("ip", "netns", "delete", candidateNS).CombinedOutput(); err != nil {
			t.Errorf("cleanup candidate namespace: %s %v", out, err)
		}
	})
	nativeWGCommand(t, candidateNS, "ip", "link", "set", "lo", "up")
	run("ip", "link", "add", "wan-b", "netns", clientNS, "type", "veth", "peer", "name", "wan-s", "netns", candidateNS)
	for _, link := range []struct{ ns, dev, addr string }{{clientNS, "wan-b", "192.0.2.6/30"}, {candidateNS, "wan-s", "192.0.2.5/30"}} {
		nativeWGCommand(t, link.ns, "ip", "address", "add", link.addr, "dev", link.dev)
		nativeWGCommand(t, link.ns, "ip", "link", "set", link.dev, "up")
	}
	candidateServerPath := filepath.Join(root, "candidate-server.conf")
	if err := os.WriteFile(candidateServerPath, []byte(strings.Replace(serverConfig, clientPublic, candidatePublic, 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	nativeWGCommand(t, candidateNS, "ip", "link", "add", "wg-server", "type", "wireguard")
	nativeWGCommand(t, candidateNS, "wg", "setconf", "wg-server", candidateServerPath)
	nativeWGCommand(t, candidateNS, "ip", "link", "set", "wg-server", "up")
	for _, value := range []string{"198.51.100.10/32", "2001:db8:10::10/128"} {
		nativeWGCommand(t, candidateNS, "ip", "address", "add", value, "dev", "lo", "nodad")
	}
	nativeWGCommand(t, candidateNS, "ip", "route", "add", "10.66.0.2/32", "dev", "wg-server")
	nativeWGCommand(t, candidateNS, "ip", "-6", "route", "add", "2001:db8:66::2/128", "dev", "wg-server")
	candidateProfile := strings.Replace(strings.Replace(profile, clientPrivate, candidatePrivate, 1), "192.0.2.1:51820", "192.0.2.5:51820", 1)
	if err := os.WriteFile(filepath.Join(root, "candidate.conf"), []byte(candidateProfile), 0o600); err != nil {
		t.Fatal(err)
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for index, ns := range []string{serverNS, candidateNS} {
		ready := filepath.Join(root, fmt.Sprintf("server-ready-%d", index))
		server := exec.Command("ip", "netns", "exec", ns, exe, "-test.run=^"+suite+"$", "-test.v")
		server.Env = append(os.Environ(), "RAZVILKA_WG_NATIVE_ROLE=server", "RAZVILKA_WG_NATIVE_ROOT="+root, "RAZVILKA_WG_NATIVE_READY="+ready)
		server.Stdout, server.Stderr = os.Stdout, os.Stderr
		if err := server.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = server.Process.Kill(); _ = server.Wait() })
		deadline := time.Now().Add(5 * time.Second)
		for {
			if _, err := os.Stat(ready); err == nil {
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("namespace HTTP/UDP server did not start")
			}
			time.Sleep(20 * time.Millisecond)
		}
	}
	client := exec.Command("ip", "netns", "exec", clientNS, exe, "-test.run=^"+suite+"$", "-test.v")
	client.Env = append(os.Environ(), "RAZVILKA_WG_NATIVE_ROLE=client", "RAZVILKA_WG_NATIVE_ROOT="+root, "RAZVILKA_WG_NATIVE_SERVER_NS="+serverNS)
	if len(selectedEndpoint) == 1 {
		client.Env = append(client.Env, "RAZVILKA_WG_NATIVE_TEST_ENDPOINT="+selectedEndpoint[0])
	}
	if output, err := client.CombinedOutput(); err != nil {
		nativeWGKernelCapture(t, clientNS, "client after failure")
		nativeWGKernelCapture(t, serverNS, "server after failure")
		t.Fatalf("native client: %v\n%s", err, output)
	} else {
		t.Log(string(output))
	}
}

func nativeWGCommand(t *testing.T, ns string, args ...string) string {
	t.Helper()
	if ns != "" {
		args = append([]string{"ip", "netns", "exec", ns}, args...)
	}
	output, err := exec.Command(args[0], args[1:]...).CombinedOutput()
	if err != nil {
		t.Fatalf("native %s: %v: %s", strings.Join(args, " "), err, output)
	}
	return strings.TrimSpace(string(output))
}

func nativeWGKeys(t *testing.T) (string, string) {
	t.Helper()
	private := nativeWGCommand(t, "", "wg", "genkey")
	cmd := exec.Command("wg", "pubkey")
	cmd.Stdin = strings.NewReader(private + "\n")
	public, err := cmd.Output()
	if err != nil {
		t.Fatal("derive fixture public key")
	}
	return private, strings.TrimSpace(string(public))
}

func nativeWGServe(t *testing.T) {
	for _, address := range []string{"198.51.100.10", "2001:db8:10::10"} {
		listener, err := net.Listen("tcp", net.JoinHostPort(address, "80"))
		if err != nil {
			t.Fatal(err)
		}
		defer listener.Close()
		go http.Serve(listener, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/plain")
			_, _ = io.WriteString(w, "native-wireguard-candidate-response")
		}))
		conn, err := net.ListenPacket("udp", net.JoinHostPort(address, "35001"))
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		go func() {
			buf := make([]byte, 128)
			for {
				n, addr, err := conn.ReadFrom(buf)
				if err != nil {
					return
				}
				_, _ = conn.WriteTo(buf[:n], addr)
			}
		}()
	}
	if err := os.WriteFile(os.Getenv("RAZVILKA_WG_NATIVE_READY"), []byte("ready"), 0o600); err != nil {
		t.Fatal(err)
	}
	select {}
}

func nativeWGClient(t *testing.T) {
	root := os.Getenv("RAZVILKA_WG_NATIVE_ROOT")
	profile, err := os.ReadFile(filepath.Join(root, "client.conf"))
	if err != nil {
		t.Fatal(err)
	}
	independent, err := os.ReadFile(filepath.Join(root, "candidate.conf"))
	if err != nil {
		t.Fatal(err)
	}
	a := NewWireGuardAdapter(nil, root)
	a.WG, a.IP, a.NativeOnly = "wg", "ip", true
	a.isolatedCandidate = true // avoid IPv6 DAD timing in this owned fixture
	a.RuntimeConfigPath = filepath.Join(root, "rz-wg.conf")
	if err := os.WriteFile(a.RuntimeConfigPath, profile, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := a.startInterface(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, family := range []string{"-4", "-6"} {
		nativeWGCommand(t, "", "ip", family, "route", "add", "default", "dev", a.Interface, "table", "206")
		source := "10.66.0.2/32"
		if family == "-6" {
			source = "2001:db8:66::2/128"
		}
		nativeWGCommand(t, "", "ip", family, "rule", "add", "priority", "70", "from", source, "lookup", "206")
	}
	for _, tc := range []struct{ name, source, address, target string }{
		{"ipv4", "10.66.0.2", "10.66.0.2/32", "198.51.100.10"},
		{"ipv6", "2001:db8:66::2", "2001:db8:66::2/128", "2001:db8:10::10"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Prove the working path answers before trying a cold same-address
			// candidate. Its higher-priority default is deliberately left intact.
			url := "http://" + net.JoinHostPort(tc.target, "80") + "/"
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			if err := sourceBoundAWGProbe(ctx, url, tc.source); err != nil {
				t.Fatal("working tunnel: ", err)
			}
			before := nativeWGCommand(t, "", "wg", "show", a.Interface, "transfer")
			transaction := filepath.Join(root, tc.name)
			if err := os.MkdirAll(transaction, 0o700); err != nil {
				t.Fatal(err)
			}
			candidateProfile := strings.Replace(string(independent), "10.66.0.2/32, 2001:db8:66::2/128", tc.address, 1)
			staged := filepath.Join(transaction, "rz-warp.conf.staged")
			if err := os.WriteFile(staged, []byte(candidateProfile), 0o600); err != nil {
				t.Fatal(err)
			}
			plan := RoutePlan{Routes: []Route{{Resolved: "wireguard", ServiceName: "native", ProbeURL: url, Sources: []string{"192.168.40.2/32"}}}}
			a.CanaryProbe = func(ctx context.Context, url, source string) error {
				if err := sourceBoundAWGProbe(ctx, url, source); err != nil {
					return err
				}
				dialer := wgSocketDialer(ctx, net.ParseIP(source), true)
				conn, err := dialer.DialContext(ctx, "udp", net.JoinHostPort(tc.target, "35001"))
				if err != nil {
					return err
				}
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
				if _, err := conn.Write([]byte("candidate-udp")); err != nil {
					return err
				}
				buf := make([]byte, 128)
				n, err := conn.Read(buf)
				if err != nil {
					return err
				}
				if string(buf[:n]) != "candidate-udp" {
					return fmt.Errorf("unexpected UDP response")
				}
				return nil
			}
			assertLive := func(label string) {
				liveCtx := context.WithValue(ctx, wgSocketInterfaceKey{}, a.Interface)
				if err := a.CanaryProbe(liveCtx, url, tc.source); err != nil {
					t.Fatalf("live after %s: %v", label, err)
				}
			}
			// Valid and wrong-peer configurations sharing the live private key
			// must both be rejected without touching either end of that session.
			_, wrongPublic := nativeWGKeys(t)
			for _, same := range []string{string(profile), strings.Replace(string(profile), nativeWGCommand(t, "", "wg", "show", a.Interface, "peers"), wrongPublic, 1)} {
				if err := os.WriteFile(staged, []byte(same), 0o600); err != nil {
					t.Fatal(err)
				}
				before = nativeWGCommand(t, "", "wg", "show", a.Interface, "transfer")
				if err := a.Canary(ctx, plan, transaction); !errors.Is(err, ErrWGCanaryIdentityInUse) {
					t.Fatal("same-key candidate not safely rejected", err)
				}
				if after := nativeWGCommand(t, "", "wg", "show", a.Interface, "transfer"); after != before {
					t.Fatal("rejected candidate disturbed live counters")
				}
				assertLive("same-key rejection")
			}
			if err := os.WriteFile(staged, []byte(candidateProfile), 0o600); err != nil {
				t.Fatal(err)
			}
			// Generic WG requires the staged policy; legacy endpoint is nil here
			// because D04 deliberately uses documentation-only transport addresses.
			state := PolicyState{Interface: a.Interface, Table: a.Table, PriorityBase: a.PriorityBase}
			bits := "128"
			if tc.name == "ipv4" {
				bits = "32"
			}
			state.Prefixes = []string{tc.target + "/" + bits}
			initializePolicyLayout(&state)
			data, _ := json.Marshal(state)
			if err := os.WriteFile(filepath.Join(transaction, "policy.staged.json"), data, 0o600); err != nil {
				t.Fatal(err)
			}
			before = nativeWGCommand(t, "", "wg", "show", a.Interface, "transfer")
			if err := a.Canary(ctx, plan, transaction); err != nil {
				t.Fatal(err)
			}
			if after := nativeWGCommand(t, "", "wg", "show", a.Interface, "transfer"); after != before {
				t.Fatal("candidate traffic used working tunnel")
			}
			if plan.Routes[0].Sources[0] != "192.168.40.2/32" {
				t.Fatal("client source scope changed")
			}
			assertLive("successful independent candidate")
			before = nativeWGCommand(t, "", "wg", "show", a.Interface, "transfer")
			// A candidate with the wrong peer key must fail even while the
			// working interface retains a recent successful handshake.
			lines := strings.Split(candidateProfile, "\n")
			for i, line := range lines {
				if strings.HasPrefix(line, "PublicKey = ") {
					lines[i] = "PublicKey = " + wrongPublic
				}
			}
			if err := os.WriteFile(staged, []byte(strings.Join(lines, "\n")), 0o600); err != nil {
				t.Fatal(err)
			}
			a.Timeout, a.HandshakeTimeout = 1200*time.Millisecond, 200*time.Millisecond
			if err := a.Canary(context.Background(), plan, transaction); err == nil {
				t.Fatal("wrong-key candidate borrowed working path")
			}
			a.Timeout, a.HandshakeTimeout = 25*time.Second, 8*time.Second
			if after := nativeWGCommand(t, "", "wg", "show", a.Interface, "transfer"); after != before {
				t.Fatal("failed candidate used working tunnel")
			}
			assertLive("failed independent candidate")
			c := *a
			c.Table, c.PriorityBase = 219, 18050
			if err := c.ensureCanaryPolicyFree(context.Background()); err != nil {
				t.Fatal(err)
			}
			if _, err := exec.Command("ip", "link", "show", "rz-wg-canary").CombinedOutput(); err == nil {
				t.Fatal("candidate interface leaked")
			}
		})
	}
}
