//go:build linux

package dataplane

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

const publicTCPBaselineNative = "RAZVILKA_PUBLIC_TCP_BASELINE_NATIVE"
const publicTCPBaselineTarget = "93.184.216.14:80"

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
	if os.Getenv("RAZVILKA_PUBLIC_TCP_DOMAIN") == "1" {
		run("-n", server, "addr", "add", "93.184.216.11/32", "dev", "lo")
		run("-n", router, "route", "add", "93.184.216.11/32", "via", "93.184.216.14")
	}
	for _, key := range []string{"net.ipv4.ip_forward=1", "net.ipv4.conf.all.rp_filter=0", "net.ipv4.conf.lan0.rp_filter=0", "net.ipv4.conf.wan0.rp_filter=0"} {
		run("netns", "exec", router, "sysctl", "-q", "-w", key)
	}
	// A foreign-looking source policy is required: main deliberately blackholes
	// the same target. The transparent socket must use original LAN source PBR.
	run("-n", router, "rule", "add", "pref", "120", "from", "192.0.2.2/32", "table", "451")
	run("-n", router, "route", "add", "table", "451", "93.184.216.14/32", "dev", "wan0")
	run("-n", router, "route", "add", "blackhole", "93.184.216.14/32")
	// Link-up starts kernel IPv6 DAD asynchronously. Finish that real topology
	// initialization before comparing ALL foreign routes; never discard drift.
	for _, ns := range []string{router, client, server} {
		deadline := time.Now().Add(4 * time.Second)
		for {
			addresses := run("-n", ns, "-6", "-j", "address", "show")
			if bytes.Contains(addresses, []byte("dadfailed")) {
				t.Fatal("owned topology DAD failed")
			}
			if !bytes.Contains(addresses, []byte("tentative")) {
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("owned topology DAD remains pending")
			}
			time.Sleep(50 * time.Millisecond)
		}
	}
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	child := exec.CommandContext(ctx, "ip", "netns", "exec", router, binary, "-test.run=^TestPublicTCPBaselineNativeChild$", "-test.count=1", "-test.timeout=22s")
	child.Env = append(os.Environ(), "RAZVILKA_PUBLIC_TCP_ROLE=router", "RAZVILKA_PUBLIC_TCP_CLIENT_NS="+client, "RAZVILKA_PUBLIC_TCP_SERVER_NS="+server)
	out, err := child.CombinedOutput()
	marker := "PUBLIC_TCP_SOURCE_PBR_ONLY_OK"
	if os.Getenv("RAZVILKA_PUBLIC_TCP_DOMAIN") == "1" {
		marker = "PUBLIC_TCP_DOMAIN_XRAY_ONLY_OK"
	}
	if err != nil || !bytes.Contains(out, []byte(marker)) {
		t.Fatalf("experimental baseline refused/failed: %v: %s", err, out)
	}
	t.Log(strings.TrimSpace(string(out)))
	for _, unsupported := range []struct {
		name     string
		selector []string
		route    bool
	}{
		{"mark", []string{"fwmark", "0x123"}, false},
		{"source-port", []string{"ipproto", "tcp", "sport", "12345"}, false},
		{"ingress", []string{"iif", "lan0"}, false},
		{"tos", []string{"tos", "0x10"}, false},
		{"route-tos", nil, true},
	} {
		t.Run("refuse-"+unsupported.name, func(t *testing.T) {
			rule := append([]string{"-n", router, "rule", "add", "pref", "115"}, unsupported.selector...)
			rule = append(rule, "table", "451")
			if unsupported.route {
				rule = []string{"-n", router, "route", "add", "table", "451", "93.184.216.14/32", "tos", "0x10", "dev", "wan0"}
			}
			run(rule...)
			defer func() { rule[3] = "del"; run(rule...) }()
			beforeRules := run("-n", router, "rule", "show")
			beforeRoutes := run("-n", router, "route", "show", "table", "all")
			beforeFirewall := publicTCPStructuralFirewall(run("netns", "exec", router, "iptables-save"))
			refused := exec.CommandContext(ctx, "ip", "netns", "exec", router, binary, "-test.run=^TestPublicTCPBaselineNativeChild$", "-test.count=1", "-test.timeout=5s")
			refused.Env = append(os.Environ(), "RAZVILKA_PUBLIC_TCP_ROLE=router", "RAZVILKA_PUBLIC_TCP_CLIENT_NS="+client, "RAZVILKA_PUBLIC_TCP_SERVER_NS="+server)
			output, err := refused.CombinedOutput()
			if err != nil || !bytes.Contains(output, []byte("PUBLIC_TCP_UNSUPPORTED_PBR_REFUSED")) {
				t.Fatalf("unsupported policy not refused: %v: %s", err, output)
			}
			afterRules := run("-n", router, "rule", "show")
			afterRoutes := run("-n", router, "route", "show", "table", "all")
			afterFirewall := publicTCPStructuralFirewall(run("netns", "exec", router, "iptables-save"))
			if !bytes.Equal(beforeRules, afterRules) || !bytes.Equal(beforeRoutes, afterRoutes) || !bytes.Equal(beforeFirewall, afterFirewall) {
				t.Fatalf("unsupported admission changed kernel policy: rules before=%s after=%s routes before=%s after=%s firewall before=%s after=%s", beforeRules, afterRules, beforeRoutes, afterRoutes, beforeFirewall, afterFirewall)
			}
		})
	}

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
		if os.Getenv("RAZVILKA_PUBLIC_TCP_DOMAIN") == "1" {
			publicTCPDomainXrayServer(t)
			return
		}
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
		if os.Getenv("RAZVILKA_PUBLIC_TCP_DOMAIN") == "1" {
			publicTCPDomainXrayClient(t)
			return
		}
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
	// This prototype admits only a closed source-only RPDB grammar. TOS,
	// marks, ports, interfaces, goto and every unknown selector refuse.
	if !publicTCPSourceOnlyPolicy(rulesBefore, routesBefore) {
		fmt.Println("PUBLIC_TCP_UNSUPPORTED_PBR_REFUSED")
		return
	}
	// Pre-existing foreign-looking chains make table preservation observable
	// even with iptables-nft, which otherwise creates tables on first rule.
	run("iptables", "-t", "nat", "-N", "FOREIGN_BASELINE_NAT")
	run("iptables", "-t", "mangle", "-N", "FOREIGN_BASELINE_MANGLE")
	filterBefore := publicTCPStructuralFirewall(run("iptables-save"))
	clientNS, serverNS := os.Getenv("RAZVILKA_PUBLIC_TCP_CLIENT_NS"), os.Getenv("RAZVILKA_PUBLIC_TCP_SERVER_NS")
	names := regexp.MustCompile(`^rzpb[0-9a-f]{12}[cs]$`)
	if !names.MatchString(clientNS) || !names.MatchString(serverNS) {
		t.Fatal("invalid owned namespaces")
	}
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4zero, Port: 18081})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	_ = listener.SetDeadline(time.Now().Add(12 * time.Second))
	capture := []string{"-w", "1", "-t", "nat", "-A", "PREROUTING", "-i", "lan0", "-s", "192.0.2.2/32", "-d", "93.184.216.14/32", "-p", "tcp", "--dport", "80", "-m", "comment", "--comment", "rz-public-baseline-experiment", "-j", "REDIRECT", "--to-ports", "18081"}
	run("iptables", capture...)
	// Return packets for the transparent socket need their own exact owned
	// mark/local route. No mark is applied to the outbound baseline socket.
	divert := []string{"-w", "1", "-t", "mangle", "-A", "PREROUTING", "-i", "wan0", "-s", "93.184.216.14/32", "-d", "192.0.2.2/32", "-p", "tcp", "-m", "socket", "--transparent", "--nowildcard", "-m", "comment", "--comment", "rz-public-baseline-return", "-j", "MARK", "--set-mark", "0x451"}
	run("iptables", divert...)
	run("ip", "rule", "add", "pref", "110", "fwmark", "0x451/0xffffffff", "table", "452")
	run("ip", "route", "add", "local", "192.0.2.2/32", "dev", "lo", "table", "452")
	defer func() {
		// Original listener/accepted flow descriptors close before selector retirement.
		_ = listener.Close()
		if late, err := listener.AcceptTCP(); !errors.Is(err, net.ErrClosed) {
			if late != nil {
				_ = late.Close()
			}
			t.Error("original listener close not confirmed")
		}
		capture[4] = "-D"
		divert[4] = "-D"
		run("iptables", capture...)
		run("iptables", divert...)
		run("ip", "rule", "del", "pref", "110", "fwmark", "0x451/0xffffffff", "table", "452")
		run("ip", "route", "del", "local", "192.0.2.2/32", "dev", "lo", "table", "452")
		if !bytes.Equal(rulesBefore, run("ip", "-4", "rule", "show")) || !bytes.Equal(routesBefore, run("ip", "-4", "route", "show", "table", "all")) || !bytes.Equal(filterBefore, publicTCPStructuralFirewall(run("iptables-save"))) {
			t.Errorf("owned cleanup changed foreign routing/firewall: rules before=%s after=%s routes before=%s after=%s firewall before=%s after=%s", rulesBefore, run("ip", "-4", "rule", "show"), routesBefore, run("ip", "-4", "route", "show", "table", "all"), filterBefore, publicTCPStructuralFirewall(run("iptables-save")))
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
	type neighbor struct{ Dst, Dev, Lladdr string }
	readOriginalNeighbor := func() neighbor {
		raw := run("ip", "-j", "neigh", "show")
		var rows []neighbor
		if err := json.Unmarshal(raw, &rows); err != nil {
			t.Fatal("neighbor inventory invalid")
		}
		var matched []neighbor
		for _, row := range rows {
			if row.Dst == observed.Source.Addr().String() && row.Dev == "lan0" {
				matched = append(matched, row)
			}
		}
		if len(matched) != 1 || matched[0].Lladdr == "" {
			t.Fatal("original LAN neighbor unavailable")
		}
		return matched[0]
	}
	neighborBefore := readOriginalNeighbor()
	ct := run("conntrack", "-L", "-p", "tcp", "--orig-src", observed.Source.Addr().String(), "--orig-dst", observed.OriginalDestination.Addr().String(), "--sport", fmt.Sprint(observed.Source.Port()), "--dport", "80", "-o", "extended")
	raw, err := accepted.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var tcpInfo *unix.TCPInfo
	var tcpErr error
	if err = raw.Control(func(fd uintptr) { tcpInfo, tcpErr = unix.GetsockoptTCPInfo(int(fd), unix.SOL_TCP, unix.TCP_INFO) }); err != nil || tcpErr != nil || tcpInfo == nil {
		t.Fatal("original accepted TCP state unavailable")
	}
	// A client may have sent FIN after its complete request. Accept that
	// active half-close only when both conntrack and the original FD agree.
	stateMatches := bytes.Contains(ct, []byte("ESTABLISHED")) && tcpInfo.State == 1 /* Linux TCP_ESTABLISHED */ || bytes.Contains(ct, []byte("FIN_WAIT")) && tcpInfo.State == 8 /* Linux TCP_CLOSE_WAIT */
	if bytes.Count(ct, []byte("mark=")) != 1 || !bytes.Contains(ct, []byte("mark=0 ")) || !stateMatches {
		t.Fatalf("original conntrack/FD state unavailable: state=%d observation=%s", tcpInfo.State, ct)
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
	if os.Getenv("RAZVILKA_PUBLIC_TCP_DOMAIN") == "1" {
		publicTCPDomainXrayCaptured(t, ctx, accepted, observed, neighborBefore.Lladdr, func() bool { return readOriginalNeighbor() == neighborBefore }, &dialer)
	} else {
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
	}
	if err = client.Wait(); err != nil {
		t.Fatal("client failed", err, clientOut.String())
	}
	clientDone = true
	if err = server.Wait(); err != nil {
		t.Fatal("server failed", err, serverErr.String())
	}
	serverDone = true
	if readOriginalNeighbor() != neighborBefore {
		t.Fatal("original LAN identity changed")
	}
	if os.Getenv("RAZVILKA_PUBLIC_TCP_DOMAIN") == "1" {
		fmt.Println("PUBLIC_TCP_DOMAIN_XRAY_ONLY_OK: actual captured payload; selected Xray vs unlisted/excluded/opaque original-source baseline; NOT Manager/firmware admission")
	} else {
		fmt.Println("PUBLIC_TCP_SOURCE_PBR_ONLY_OK: actual original-destination capture; source IP and source-only PBR preserved; NOT production/domain/Xray admission")
	}
}

func publicTCPStructuralFirewall(raw []byte) []byte {
	lines := []string{}
	for _, line := range strings.Split(string(raw), "\n") {
		if !strings.HasPrefix(line, "#") {
			lines = append(lines, line)
		}
	}
	return regexp.MustCompile(`\[[0-9]+:[0-9]+\]`).ReplaceAll([]byte(strings.Join(lines, "\n")), []byte("[0:0]"))
}

func publicTCPSourceOnlyPolicy(rules, routes []byte) bool {
	for _, line := range strings.Split(strings.TrimSpace(string(rules)), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 5 || !strings.HasSuffix(fields[0], ":") || fields[1] != "from" || fields[3] != "lookup" {
			return false
		}
		if _, err := strconv.ParseUint(strings.TrimSuffix(fields[0], ":"), 10, 32); err != nil {
			return false
		}
		if fields[2] != "all" {
			if prefix, err := netip.ParsePrefix(fields[2]); err != nil || !prefix.Addr().Is4() {
				if address, err := netip.ParseAddr(fields[2]); err != nil || !address.Is4() {
					return false
				}
			}
		}
		switch fields[4] {
		case "local", "main", "default":
		default:
			if table, err := strconv.ParseUint(fields[4], 10, 32); err != nil || table == 0 {
				return false
			}
		}
	}
	for _, field := range strings.Fields(string(routes)) {
		if field == "tos" || field == "dsfield" {
			return false
		}
	}
	return len(strings.TrimSpace(string(rules))) != 0
}

func TestPublicTCPSourceOnlyPolicyClosedGrammar(t *testing.T) {
	base := []byte("0: from all lookup local\n120: from 192.0.2.2 lookup 451\n32766: from all lookup main\n32767: from all lookup default\n")
	if !publicTCPSourceOnlyPolicy(base, nil) {
		t.Fatal("source-only fixture rejected")
	}
	for _, selector := range []string{"tos 0x10", "fwmark 1", "iif lan0", "ipproto tcp sport 12345", "uidrange 1-2", "not", "suppress_prefixlength 0"} {
		if publicTCPSourceOnlyPolicy(append(append([]byte(nil), base...), []byte("115: from all "+selector+" lookup 451\n")...), nil) {
			t.Fatalf("unknown selector accepted: %s", selector)
		}
	}
	if publicTCPSourceOnlyPolicy(base, []byte("93.184.216.14 tos 0x10 dev wan0 table 451")) {
		t.Fatal("route TOS accepted without original TOS authority")
	}
}
