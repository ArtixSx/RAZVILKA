//go:build linux

package dataplane

import (
	"context"
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
	if os.Getenv("RAZVILKA_WG_NATIVE") != "1" {
		t.Skip("requires exclusive Linux VM: RAZVILKA_WG_NATIVE=1 go test ./internal/dataplane -run '^TestWGNativeCandidateIsolation$' -count=1 -v")
	}
	if role := os.Getenv("RAZVILKA_WG_NATIVE_ROLE"); role != "" {
		if role == "server" {
			nativeWGServe(t)
		} else {
			nativeWGClient(t)
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
	serverPrivate, serverPublic := nativeWGKeys(t)
	clientPrivate, clientPublic := nativeWGKeys(t)
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
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	server := exec.Command("ip", "netns", "exec", serverNS, exe, "-test.run=^TestWGNativeCandidateIsolation$", "-test.v")
	server.Env = append(os.Environ(), "RAZVILKA_WG_NATIVE_ROLE=server", "RAZVILKA_WG_NATIVE_ROOT="+root)
	server.Stdout, server.Stderr = os.Stdout, os.Stderr
	if err := server.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Process.Kill(); _ = server.Wait() })
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Stat(filepath.Join(root, "server-ready")); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("namespace HTTP/UDP server did not start")
		}
		time.Sleep(20 * time.Millisecond)
	}
	client := exec.Command("ip", "netns", "exec", clientNS, exe, "-test.run=^TestWGNativeCandidateIsolation$", "-test.v")
	client.Env = append(os.Environ(), "RAZVILKA_WG_NATIVE_ROLE=client", "RAZVILKA_WG_NATIVE_ROOT="+root)
	if output, err := client.CombinedOutput(); err != nil {
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
	if err := os.WriteFile(filepath.Join(os.Getenv("RAZVILKA_WG_NATIVE_ROOT"), "server-ready"), []byte("ready"), 0o600); err != nil {
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
			if tc.name == "ipv6" {
				// Both fixtures deliberately share a peer key as well as Address.
				// After a candidate session, reset the working fixture to force a
				// fresh handshake instead of reusing its superseded Noise session.
				if err := a.stopInterface(context.Background()); err != nil {
					t.Fatal(err)
				}
				if err := a.startInterface(context.Background()); err != nil {
					t.Fatal(err)
				}
				for _, family := range []string{"-4", "-6"} {
					nativeWGCommand(t, "", "ip", family, "route", "add", "default", "dev", a.Interface, "table", "206")
				}
			}
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
			candidateProfile := strings.Replace(string(profile), "10.66.0.2/32, 2001:db8:66::2/128", tc.address, 1)
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
			if err := a.Canary(ctx, plan, transaction); err != nil {
				t.Fatal(err)
			}
			if after := nativeWGCommand(t, "", "wg", "show", a.Interface, "transfer"); after != before {
				t.Fatal("candidate traffic used working tunnel")
			}
			if plan.Routes[0].Sources[0] != "192.168.40.2/32" {
				t.Fatal("client source scope changed")
			}
			// A candidate with the wrong peer key must fail even while the
			// working interface retains a recent successful handshake.
			_, wrongPublic := nativeWGKeys(t)
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
