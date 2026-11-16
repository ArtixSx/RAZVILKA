//go:build linux && amd64 && razvilka_native_fixture

package dataplane

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// Compiler/kernel counterexample only. This does not construct a production
// accepted-FD owner or replace the strict application service/deadline gate.
const collisionClient = "192.168.60.2"
const collisionReal = "1.1.1.2"
const collisionSynthetic = "198.18.0.17"
const collisionPort = 40031

type collisionMessage struct {
	Kind       string `json:"kind"`
	Value      string `json:"value,omitempty"`
	Local      string `json:"local,omitempty"`
	OtherLocal string `json:"other_local,omitempty"`
}

type collisionChild struct {
	cmd    *exec.Cmd
	in     io.WriteCloser
	scan   *bufio.Scanner
	joined bool
}

func (c *collisionChild) read(t *testing.T) collisionMessage {
	t.Helper()
	if !c.scan.Scan() {
		t.Fatalf("fixture child ended before protocol message: %v", c.scan.Err())
	}
	var m collisionMessage
	if err := json.Unmarshal(c.scan.Bytes(), &m); err != nil {
		t.Fatal("invalid bounded fixture protocol", err)
	}
	return m
}
func (c *collisionChild) send(t *testing.T, command string) {
	t.Helper()
	if _, err := io.WriteString(c.in, command+"\n"); err != nil {
		t.Fatal(err)
	}
}
func (c *collisionChild) join(t *testing.T) {
	t.Helper()
	c.send(t, "stop")
	if err := c.in.Close(); err != nil {
		t.Fatal(err)
	}
	c.joined = true // The sole Wait remains sole even on an error.
	if err := c.cmd.Wait(); err != nil {
		t.Fatal("fixture child did not join", err)
	}
}

func TestDomainBaselineTupleCollisionNative(t *testing.T) {
	if os.Getenv("RAZVILKA_DOMAIN_TUPLE_COLLISION") != "1" {
		t.Skip("explicit disposable compiler/kernel diagnostic")
	}
	if os.Geteuid() != 0 || os.Getpid() != 1 {
		t.Fatal("require isolated PID1 fixture")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 35*time.Second)
	defer cancel()
	run := func(name string, args ...string) []byte {
		t.Helper()
		out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
		if err != nil {
			t.Fatalf("fixture %s %v: %v %s", name, args, err, out)
		}
		return out
	}
	for _, ns := range []string{"rz-collision-client", "rz-collision-remote"} {
		run("ip", "netns", "add", ns)
		t.Cleanup(func() {
			cleanup, done := context.WithTimeout(context.Background(), 2*time.Second)
			defer done()
			if out, err := exec.CommandContext(cleanup, "ip", "netns", "del", ns).CombinedOutput(); err != nil {
				t.Errorf("owned netns cleanup: %v %s", err, out)
			}
		})
	}
	run("ip", "link", "set", "lo", "up")
	for _, link := range []struct{ router, peer, ns, routerIP, peerIP string }{
		{"lan0", "c0", "rz-collision-client", "192.168.60.1/24", collisionClient + "/24"},
		{"wan0", "r0", "rz-collision-remote", "1.1.1.1/24", collisionReal + "/24"},
	} {
		run("ip", "link", "add", link.router, "type", "veth", "peer", "name", link.peer)
		run("ip", "link", "set", link.peer, "netns", link.ns)
		run("ip", "addr", "add", link.routerIP, "dev", link.router)
		run("ip", "link", "set", link.router, "up")
		run("ip", "-n", link.ns, "link", "set", "lo", "up")
		run("ip", "-n", link.ns, "addr", "add", link.peerIP, "dev", link.peer)
		run("ip", "-n", link.ns, "link", "set", link.peer, "up")
	}
	run("ip", "-n", "rz-collision-client", "route", "add", "default", "via", "192.168.60.1")
	run("ip", "-n", "rz-collision-remote", "route", "add", "default", "via", "1.1.1.1")
	run("ip", "addr", "add", collisionSynthetic+"/32", "dev", "lan0")
	if err := os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1\n"), 0600); err != nil {
		t.Fatal(err)
	}
	// Reverse-path filtering must not substitute another failure for the exact
	// packet-predicate counterexample. These sysctls belong to the new netns.
	for _, iface := range []string{"all", "default", "lan0", "wan0"} {
		if err := os.WriteFile("/proc/sys/net/ipv4/conf/"+iface+"/rp_filter", []byte("0\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.ParseIP(collisionSynthetic), Port: 443})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	start := func(ns, role string) *collisionChild {
		t.Helper()
		cmd := exec.CommandContext(ctx, "ip", "netns", "exec", ns, os.Args[0], "-test.run=^TestDomainBaselineTupleCollisionNativeHelper$", "-test.timeout=30s")
		cmd.Env = append(os.Environ(), "RAZVILKA_COLLISION_ROLE="+role)
		cmd.Stderr = os.Stderr
		in, err := cmd.StdinPipe()
		if err != nil {
			t.Fatal(err)
		}
		out, err := cmd.StdoutPipe()
		if err != nil {
			_ = in.Close()
			t.Fatal(err)
		}
		c := &collisionChild{cmd: cmd, in: in, scan: bufio.NewScanner(out)}
		c.scan.Buffer(make([]byte, 1024), 16<<10)
		if err := cmd.Start(); err != nil {
			_ = in.Close()
			_ = out.Close()
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if !c.joined {
				_ = c.in.Close()
				_ = cmd.Process.Kill()
				c.joined = true
				if err := cmd.Wait(); err != nil && !errors.As(err, new(*exec.ExitError)) {
					t.Errorf("fixture cleanup Wait: %v", err)
				}
			}
		})
		return c
	}
	server := start("rz-collision-remote", "server")
	if m := server.read(t); m.Kind != "ready" {
		t.Fatal("server readiness", m)
	}
	client := start("rz-collision-client", "client")
	m := client.read(t)
	wantLocal := net.JoinHostPort(collisionClient, strconv.Itoa(collisionPort))
	if m.Kind != "ready" || m.Local != wantLocal || m.OtherLocal != wantLocal {
		t.Fatal("actual client same-port distinct destinations not proven", m)
	}
	if err := listener.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	accepted, err := listener.AcceptTCP()
	if err != nil {
		t.Fatal(err)
	}
	defer accepted.Close()
	if accepted.RemoteAddr().String() != wantLocal || accepted.LocalAddr().String() != collisionSynthetic+":443" {
		t.Fatal("synthetic accepted tuple mismatch")
	}
	exchange := func(command string, wantFailure bool) {
		t.Helper()
		client.send(t, command)
		got := client.read(t)
		if (!wantFailure && got.Kind != "echo") || (wantFailure && got.Kind != "intercepted") || got.Value != command {
			t.Fatal("client exchange", got, command, wantFailure)
		}
		remote := server.read(t)
		if remote.Kind != "sent" || remote.Value != command {
			t.Fatal("remote did not send exact reply", remote)
		}
	}
	exchange("control", false)
	t.Log("DOMAIN_TUPLE_NO_EFFECT_CONTROL direct_echo=true same_client_port_different_destination=true")
	_, capture := domainTCPBaselineKernelModel(t)
	capture.Client.Address, capture.Client.Interface = netip.MustParseAddr(collisionClient), "lan0"
	capture.Xray.RealIP = netip.MustParseAddr(collisionReal)
	plan, err := compileDomainTCPBaselineFlow(domainTCPBaselineFlowSpec{Capture: capture, Source: netip.AddrPortFrom(netip.MustParseAddr(collisionClient), collisionPort), Target: netip.AddrPortFrom(netip.MustParseAddr(collisionReal), 443), Egress: "wan0"})
	if err != nil || len(plan.Effects) != 5 {
		t.Fatal("exact existing compiler", err)
	}
	added := 0
	cleanupRules := func() {
		for added > 0 {
			effect := plan.Effects[added-1]
			name := "iptables-legacy"
			if effect.Tool == PolicyEffectIP {
				name = "ip"
			}
			cleanup, done := context.WithTimeout(context.Background(), 2*time.Second)
			out, err := exec.CommandContext(cleanup, name, effect.Delete...).CombinedOutput()
			done()
			if err != nil {
				t.Errorf("exact reverse effect cleanup: %v %s", err, out)
				return
			}
			added--
		}
	}
	t.Cleanup(cleanupRules)
	for _, effect := range plan.Effects {
		name := "iptables-legacy"
		if effect.Tool == PolicyEffectIP {
			name = "ip"
		}
		run(name, effect.Add...)
		added++
	}
	count := func(table string) uint64 {
		t.Helper()
		out := string(run("iptables-legacy", "-t", table, "-L", "PREROUTING", "-n", "-v", "-x"))
		var found bool
		var packets uint64
		for _, line := range strings.Split(out, "\n") {
			fields := strings.Fields(line)
			if len(fields) < 3 {
				continue
			}
			n, err := strconv.ParseUint(fields[0], 10, 64)
			if err != nil {
				continue
			}
			want := "MARK"
			if table == "raw" {
				want = "CT"
			}
			if found || fields[2] != want {
				t.Fatal("unexpected fixture packet row", line)
			}
			found, packets = true, n
		}
		if !found {
			t.Fatal("missing exact fixture packet row", table)
		}
		return packets
	}
	rawBefore, markBefore := count("raw"), count("mangle")
	exchange("second-port", false)
	if count("raw") != rawBefore || count("mangle") != markBefore {
		t.Fatal("adjacent source port matched exact tuple")
	}
	t.Log("DOMAIN_TUPLE_SECOND_PORT_CONTROL direct_echo=true exact_counters_unchanged=true")
	exchange("collision", true)
	rawAfter, markAfter := count("raw"), count("mangle")
	if rawAfter <= rawBefore || markAfter <= markBefore {
		t.Fatal("direct reply interception not established", rawBefore, rawAfter, markBefore, markAfter)
	}
	t.Logf("DOMAIN_TUPLE_COLLISION_CONFIRMED raw_delta=%d mark_delta=%d direct_reply_failed=true remote_reply_sent=true compiler_effects=5 application_owner_proof=false", rawAfter-rawBefore, markAfter-markBefore)
	cleanupRules()
	if added != 0 {
		t.Fatal("exact rules retained")
	}
	client.join(t)
	server.join(t)
	t.Log("DOMAIN_TUPLE_CLEANUP exact_effects_removed=true children_joined=true")
}

func TestDomainBaselineTupleCollisionNativeHelper(t *testing.T) {
	role := os.Getenv("RAZVILKA_COLLISION_ROLE")
	if role == "" {
		t.Skip("private child protocol only")
	}
	var outMu sync.Mutex
	emit := func(m collisionMessage) {
		outMu.Lock()
		defer outMu.Unlock()
		if err := json.NewEncoder(os.Stdout).Encode(m); err != nil {
			t.Error(err)
		}
	}
	commands := bufio.NewScanner(os.Stdin)
	commands.Buffer(make([]byte, 1024), 4096)
	if role == "server" {
		listener, err := net.Listen("tcp4", collisionReal+":443")
		if err != nil {
			t.Fatal(err)
		}
		var mu sync.Mutex
		var conns []net.Conn
		var wg sync.WaitGroup
		acceptDone := make(chan struct{})
		go func() {
			defer close(acceptDone)
			for {
				conn, err := listener.Accept()
				if err != nil {
					return
				}
				mu.Lock()
				conns = append(conns, conn)
				tooMany := len(conns) > 2
				mu.Unlock()
				if tooMany {
					_ = conn.Close()
					return
				}
				wg.Add(1)
				go func() {
					defer wg.Done()
					defer conn.Close()
					scan := bufio.NewScanner(conn)
					scan.Buffer(make([]byte, 1024), 4096)
					for scan.Scan() {
						text := scan.Text()
						if _, err := io.WriteString(conn, text+"\n"); err != nil {
							return
						}
						emit(collisionMessage{Kind: "sent", Value: text})
					}
				}()
			}
		}()
		defer func() {
			_ = listener.Close()
			<-acceptDone
			mu.Lock()
			for _, conn := range conns {
				_ = conn.Close()
			}
			mu.Unlock()
			wg.Wait()
		}()
		emit(collisionMessage{Kind: "ready"})
		if !commands.Scan() || commands.Text() != "stop" {
			t.Fatal("server expected joined stop")
		}
		return
	}
	if role != "client" {
		t.Fatal("unknown role")
	}
	dial := func(port int, address string) net.Conn {
		t.Helper()
		d := net.Dialer{Timeout: 2 * time.Second, LocalAddr: &net.TCPAddr{IP: net.ParseIP(collisionClient), Port: port}, Control: func(_, _ string, raw syscall.RawConn) error {
			var result error
			err := raw.Control(func(fd uintptr) { result = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1) })
			return errors.Join(err, result)
		}}
		conn, err := d.Dial("tcp4", address+":443")
		if err != nil {
			t.Fatal("actual same-port client dial", err)
		}
		return conn
	}
	direct := dial(collisionPort, collisionReal)
	defer direct.Close()
	synthetic := dial(collisionPort, collisionSynthetic)
	defer synthetic.Close()
	other := dial(collisionPort+1, collisionReal)
	defer other.Close()
	emit(collisionMessage{Kind: "ready", Local: direct.LocalAddr().String(), OtherLocal: synthetic.LocalAddr().String()})
	for commands.Scan() {
		command := commands.Text()
		if command == "stop" {
			return
		}
		if command != "control" && command != "second-port" && command != "collision" {
			t.Fatal("unknown client command")
		}
		conn := direct
		if command == "second-port" {
			conn = other
		}
		if err := conn.SetDeadline(time.Now().Add(time.Second)); err != nil {
			t.Fatal(err)
		}
		if _, err := fmt.Fprintln(conn, command); err != nil {
			t.Fatal("request was not sent", err)
		}
		line, err := bufio.NewReaderSize(conn, 1024).ReadString('\n')
		if command == "collision" {
			var timeout net.Error
			if err == nil || !(errors.Is(err, syscall.ECONNRESET) || errors.Is(err, io.EOF) || errors.As(err, &timeout) && timeout.Timeout()) {
				t.Fatal("no bounded direct delivery failure", err, line)
			}
			emit(collisionMessage{Kind: "intercepted", Value: command})
			continue
		}
		if err != nil || line != command+"\n" {
			t.Fatal("direct control failed", err, line)
		}
		emit(collisionMessage{Kind: "echo", Value: command})
	}
	t.Fatal("client protocol ended without joined stop")
}
