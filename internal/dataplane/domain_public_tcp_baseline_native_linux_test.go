//go:build linux

package dataplane

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

const publicTCPBaselineNative = "RAZVILKA_PUBLIC_TCP_BASELINE_NATIVE"
const publicTCPBaselineTarget = "93.184.216.14:8080"

// EXPERIMENT ONLY. This is a kernel feasibility test, not a production grant,
// Manager admission, domain/Xray acceptance or firmware-equivalence proof.
// Every selector, route, process and conntrack is in three fresh namespaces.
// Source-port/iif/mark-dependent firmware PBR is deliberately NOT claimed.
func TestPublicTCPBaselineNative(t *testing.T) {
	if os.Getenv(publicTCPBaselineNative) != "1" {
		t.Skip("explicit root-only isolated baseline experiment")
	}
	if os.Geteuid() != 0 {
		t.Fatal("root required")
	}
	for _, tool := range []string{"ip", "iptables", "sysctl", "conntrack"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Fatal(err)
		}
	}
	var nonce [6]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		t.Fatal(err)
	}
	prefix := "rzpb" + hex.EncodeToString(nonce[:])
	router, client, server := prefix+"r", prefix+"c", prefix+"s"
	run := func(args ...string) []byte {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
		defer cancel()
		out, err := exec.CommandContext(ctx, "ip", args...).CombinedOutput()
		if err != nil {
			t.Fatalf("owned namespace command %v: %v: %s", args, err, out)
		}
		return out
	}
	created := []string{}
	t.Cleanup(func() {
		for i := len(created) - 1; i >= 0; i-- {
			ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
			out, err := exec.CommandContext(ctx, "ip", "netns", "delete", created[i]).CombinedOutput()
			cancel()
			if err != nil {
				t.Errorf("namespace cleanup pending %s: %v: %s", created[i], err, out)
			}
		}
		ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
		defer cancel()
		out, err := exec.CommandContext(ctx, "ip", "netns", "list").CombinedOutput()
		if err != nil {
			t.Error("namespace absence unknown")
			return
		}
		for _, line := range strings.Split(string(out), "\n") {
			fields := strings.Fields(line)
			if len(fields) > 0 && strings.HasPrefix(fields[0], prefix) {
				t.Error("original experiment namespace retained")
			}
		}
	})
	for _, ns := range []string{router, client, server} {
		run("netns", "add", ns)
		created = append(created, ns)
		run("-n", ns, "link", "set", "lo", "up")
	}
	for _, pair := range []struct{ inside, peer, ns string }{{"lan0", "client0", client}, {"wan0", "server0", server}} {
		run("-n", router, "link", "add", pair.inside, "type", "veth", "peer", "name", pair.peer)
		run("-n", router, "link", "set", pair.peer, "netns", pair.ns)
		run("-n", router, "link", "set", pair.inside, "up")
		run("-n", pair.ns, "link", "set", pair.peer, "up")
	}
	run("-n", router, "addr", "add", "192.0.2.1/24", "dev", "lan0")
	run("-n", client, "addr", "add", "192.0.2.2/24", "dev", "client0")
	run("-n", router, "addr", "add", "93.184.216.13/30", "dev", "wan0")
	run("-n", server, "addr", "add", "93.184.216.14/30", "dev", "server0")
	run("-n", client, "route", "add", "default", "via", "192.0.2.1")
	run("-n", server, "route", "add", "192.0.2.0/24", "via", "93.184.216.13")
	for _, key := range []string{"net.ipv4.conf.all.rp_filter=0", "net.ipv4.conf.lan0.rp_filter=0", "net.ipv4.conf.wan0.rp_filter=0"} {
		run("netns", "exec", router, "sysctl", "-q", "-w", key)
	}
	// A foreign-looking source policy is required: main deliberately blackholes
	// the same target. The transparent socket must use original LAN source PBR.
	run("-n", router, "rule", "add", "pref", "120", "from", "192.0.2.2/32", "table", "451")
	run("-n", router, "route", "add", "table", "451", "93.184.216.14/32", "dev", "wan0")
	run("-n", router, "route", "add", "blackhole", "93.184.216.14/32")
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	child := exec.CommandContext(ctx, "ip", "netns", "exec", router, binary, "-test.run=^TestPublicTCPBaselineNativeChild$", "-test.count=1", "-test.timeout=22s")
	child.Env = append(os.Environ(), "RAZVILKA_PUBLIC_TCP_ROLE=router", "RAZVILKA_PUBLIC_TCP_CLIENT_NS="+client, "RAZVILKA_PUBLIC_TCP_SERVER_NS="+server)
	out, err := child.CombinedOutput()
	if err != nil || !bytes.Contains(out, []byte("PUBLIC_TCP_SOURCE_PBR_ONLY_OK")) {
		t.Fatalf("experimental baseline refused/failed: %v: %s", err, out)
	}
	t.Log(strings.TrimSpace(string(out)))
}

func TestPublicTCPBaselineNativeChild(t *testing.T) {
	if os.Getenv(publicTCPBaselineNative) != "1" {
		t.Skip("owned parent only")
	}
	role := os.Getenv("RAZVILKA_PUBLIC_TCP_ROLE")
	if role == "" {
		t.Skip("owned parent only")
	}
	self, e1 := os.Readlink("/proc/self/ns/net")
	init, e2 := os.Readlink("/proc/1/ns/net")
	if e1 != nil || e2 != nil || self == init {
		t.Fatal("fresh namespace required")
	}
	switch role {
	case "server":
		l, err := net.ListenTCP("tcp4", net.TCPAddrFromAddrPort(netip.MustParseAddrPort(publicTCPBaselineTarget)))
		if err != nil {
			t.Fatal(err)
		}
		defer l.Close()
		_ = l.SetDeadline(time.Now().Add(15 * time.Second))
		fmt.Println("BASELINE_SERVER_READY")
		c, err := l.AcceptTCP()
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
		line, err := bufio.NewReader(c).ReadString('\n')
		if err != nil || line != "original-payload\n" {
			t.Fatal("payload mismatch", err)
		}
		peer := c.RemoteAddr().(*net.TCPAddr).AddrPort()
		if peer.Addr() != netip.MustParseAddr("192.0.2.2") {
			t.Fatal("baseline lost original LAN source")
		}
		_, err = io.WriteString(c, "baseline-source="+peer.Addr().String()+"\n")
		if err != nil {
			t.Fatal(err)
		}
	case "client":
		ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
		defer cancel()
		c, err := (&net.Dialer{}).DialContext(ctx, "tcp4", publicTCPBaselineTarget)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(8 * time.Second))
		if _, err = io.WriteString(c, "original-payload\n"); err != nil {
			t.Fatal(err)
		}
		line, err := bufio.NewReader(c).ReadString('\n')
		if err != nil || line != "baseline-source=192.0.2.2\n" {
			t.Fatal("baseline response mismatch", err)
		}
	case "router":
		publicTCPBaselineRouterExperiment(t)
	default:
		t.Fatal("unknown experiment role")
	}
}

func publicTCPBaselineRouterExperiment(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 18*time.Second)
	defer cancel()
	run := func(name string, args ...string) []byte {
		t.Helper()
		cctx, ccancel := context.WithTimeout(ctx, 3*time.Second)
		defer ccancel()
		out, err := exec.CommandContext(cctx, name, args...).CombinedOutput()
		if err != nil {
			t.Fatalf("experiment %s %v: %v: %s", name, args, err, out)
		}
		return out
	}
	// Capture the complete rule and route images before adding owned return PBR.
	rulesBefore := run("ip", "-4", "rule", "show")
	routesBefore := run("ip", "-4", "route", "show", "table", "all")
	run("iptables", "-t", "nat", "-S")
	run("iptables", "-t", "mangle", "-S")
	structuralFirewall := func(raw []byte) []byte {
		lines := []string{}
		for _, line := range strings.Split(string(raw), "\n") {
			if !strings.HasPrefix(line, "#") {
				lines = append(lines, line)
			}
		}
		return regexp.MustCompile(`\[[0-9]+:[0-9]+\]`).ReplaceAll([]byte(strings.Join(lines, "\n")), []byte("[0:0]"))
	}
	filterBefore := structuralFirewall(run("iptables-save"))
	clientNS, serverNS := os.Getenv("RAZVILKA_PUBLIC_TCP_CLIENT_NS"), os.Getenv("RAZVILKA_PUBLIC_TCP_SERVER_NS")
	names := regexp.MustCompile(`^rzpb[0-9a-f]{12}[cs]$`)
	if !names.MatchString(clientNS) || !names.MatchString(serverNS) {
		t.Fatal("invalid owned namespaces")
	}
	// Unknown policy selectors are unsupported, not a reason to use router direct.
	for _, word := range []string{"fwmark", "sport", "dport", "ipproto", " iif ", " oif ", " uidrange ", " l3mdev"} {
		if bytes.Contains(rulesBefore, []byte(word)) {
			t.Fatal("unsupported baseline PBR selector")
		}
	}
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4zero, Port: 18081})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	_ = listener.SetDeadline(time.Now().Add(12 * time.Second))
	capture := []string{"-w", "1", "-t", "nat", "-A", "PREROUTING", "-i", "lan0", "-s", "192.0.2.2/32", "-d", "93.184.216.14/32", "-p", "tcp", "--dport", "8080", "-m", "comment", "--comment", "rz-public-baseline-experiment", "-j", "REDIRECT", "--to-ports", "18081"}
	run("iptables", capture...)
	// Return packets for the transparent socket need their own exact owned
	// mark/local route. No mark is applied to the outbound baseline socket.
	divert := []string{"-w", "1", "-t", "mangle", "-A", "PREROUTING", "-i", "wan0", "-s", "93.184.216.14/32", "-d", "192.0.2.2/32", "-p", "tcp", "-m", "socket", "--transparent", "--nowildcard", "-m", "comment", "--comment", "rz-public-baseline-return", "-j", "MARK", "--set-mark", "0x451"}
	run("iptables", divert...)
	run("ip", "rule", "add", "pref", "110", "fwmark", "0x451/0xffffffff", "table", "452")
	run("ip", "route", "add", "local", "192.0.2.2/32", "dev", "lo", "table", "452")
	defer func() {
		capture[4] = "-D"
		divert[4] = "-D"
		run("iptables", capture...)
		run("iptables", divert...)
		run("ip", "rule", "del", "pref", "110", "fwmark", "0x451/0xffffffff", "table", "452")
		run("ip", "route", "del", "local", "192.0.2.2/32", "dev", "lo", "table", "452")
		if !bytes.Equal(rulesBefore, run("ip", "-4", "rule", "show")) || !bytes.Equal(routesBefore, run("ip", "-4", "route", "show", "table", "all")) || !bytes.Equal(filterBefore, structuralFirewall(run("iptables-save"))) {
			t.Error("owned cleanup changed foreign routing/firewall")
		}
	}()
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	child := func(ns, role string) *exec.Cmd {
		c := exec.CommandContext(ctx, "ip", "netns", "exec", ns, binary, "-test.run=^TestPublicTCPBaselineNativeChild$", "-test.count=1", "-test.timeout=15s")
		c.Env = append(os.Environ(), "RAZVILKA_PUBLIC_TCP_ROLE="+role)
		return c
	}
	server := child(serverNS, "server")
	pipe, err := server.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var serverErr bytes.Buffer
	server.Stderr = &serverErr
	if err = server.Start(); err != nil {
		t.Fatal(err)
	}
	serverDone := false
	defer func() {
		if !serverDone {
			_ = server.Process.Kill()
			_ = server.Wait()
		}
	}()
	ready := make(chan string, 1)
	go func() { line, _ := bufio.NewReader(pipe).ReadString('\n'); ready <- line }()
	select {
	case line := <-ready:
		if line != "BASELINE_SERVER_READY\n" {
			t.Fatal("server readiness refused", line)
		}
	case <-ctx.Done():
		t.Fatal("server readiness timed out")
	}
	client := child(clientNS, "client")
	var clientOut bytes.Buffer
	client.Stdout = &clientOut
	client.Stderr = &clientOut
	if err = client.Start(); err != nil {
		t.Fatal(err)
	}
	clientDone := false
	defer func() {
		if !clientDone {
			_ = client.Process.Kill()
			_ = client.Wait()
		}
	}()
	accepted, err := listener.AcceptTCP()
	if err != nil {
		t.Fatal(err)
	}
	defer accepted.Close()
	_ = accepted.SetDeadline(time.Now().Add(8 * time.Second))
	observed, err := observeDomainPolicyTCPSocket(accepted)
	if err != nil || observed.Source.Addr() != netip.MustParseAddr("192.0.2.2") || observed.OriginalDestination != netip.MustParseAddrPort(publicTCPBaselineTarget) {
		t.Fatal("original capture observation refused", observed, err)
	}
	// Actual neighbor read supplies MAC/iif bookends, not a supplied flow DTO.
	neighBefore := run("ip", "-j", "neigh", "show", "to", observed.Source.Addr().String(), "dev", "lan0")
	var neighbors []struct{ Dst, Dev, Lladdr string }
	if json.Unmarshal(neighBefore, &neighbors) != nil || len(neighbors) != 1 || neighbors[0].Dev != "lan0" || neighbors[0].Lladdr == "" {
		t.Fatal("original LAN neighbor unavailable")
	}
	ct := run("conntrack", "-L", "-p", "tcp", "--orig-src", observed.Source.Addr().String(), "--orig-dst", observed.OriginalDestination.Addr().String(), "--sport", fmt.Sprint(observed.Source.Port()), "--dport", "8080", "-o", "extended")
	if !bytes.Contains(ct, []byte("mark=0")) || !bytes.Contains(ct, []byte("ESTABLISHED")) {
		t.Fatal("original conntrack scope unavailable")
	}
	route := run("ip", "-4", "route", "get", observed.OriginalDestination.Addr().String(), "from", observed.Source.Addr().String(), "iif", "lan0")
	if !bytes.Contains(route, []byte("table 451")) || !bytes.Contains(route, []byte("dev wan0")) {
		t.Fatal("source PBR did not select original route")
	}
	dialer := net.Dialer{LocalAddr: &net.TCPAddr{IP: net.IP(observed.Source.Addr().AsSlice())}, Control: func(_, _ string, raw syscall.RawConn) error {
		var optionErr error
		err := raw.Control(func(fd uintptr) { optionErr = unix.SetsockoptInt(int(fd), unix.SOL_IP, unix.IP_TRANSPARENT, 1) })
		if err != nil {
			return err
		}
		return optionErr
	}}
	upstream, err := dialer.DialContext(ctx, "tcp4", observed.OriginalDestination.String())
	if err != nil {
		t.Fatal("source-preserving baseline dial failed", err)
	}
	defer upstream.Close()
	_ = upstream.SetDeadline(time.Now().Add(6 * time.Second))
	line, err := bufio.NewReader(accepted).ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if _, err = io.WriteString(upstream, line); err != nil {
		t.Fatal(err)
	}
	response, err := bufio.NewReader(upstream).ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if _, err = io.WriteString(accepted, response); err != nil {
		t.Fatal(err)
	}
	if err = client.Wait(); err != nil {
		t.Fatal("client failed", err, clientOut.String())
	}
	clientDone = true
	if err = server.Wait(); err != nil {
		t.Fatal("server failed", err, serverErr.String())
	}
	serverDone = true
	neighAfter := run("ip", "-j", "neigh", "show", "to", observed.Source.Addr().String(), "dev", "lan0")
	var closing []struct{ Dst, Dev, Lladdr string }
	if json.Unmarshal(neighAfter, &closing) != nil || len(closing) != 1 || closing[0].Dst != neighbors[0].Dst || closing[0].Dev != neighbors[0].Dev || closing[0].Lladdr != neighbors[0].Lladdr {
		t.Fatal("original LAN identity changed")
	}
	fmt.Println("PUBLIC_TCP_SOURCE_PBR_ONLY_OK: actual original-destination capture; source IP and source-only PBR preserved; NOT production/domain/Xray admission")
}
