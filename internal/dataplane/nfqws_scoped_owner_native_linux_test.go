//go:build linux

package dataplane

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/components"
)

// This entry creates only ROOT's private peer netns or sends its own test UDP.
// It is never dispatched by production main or installed as a daemon.
func TestNFQWSScopedNativeEntry(t *testing.T) {
	for i, arg := range os.Args {
		if arg == "nfqws-scoped-peer" {
			if len(os.Args[i:]) != 2 || os.WriteFile(os.Args[i+1], []byte("ready\n"), 0600) != nil {
				os.Exit(8)
			}
			time.Sleep(30 * time.Second)
			os.Exit(0)
		}
		if arg == "nfqws-scoped-send" {
			if len(os.Args[i:]) != 3 {
				os.Exit(8)
			}
			local, err := net.ResolveUDPAddr("udp", net.JoinHostPort(os.Args[i+1], "0"))
			if err != nil {
				os.Exit(8)
			}
			remote, err := net.ResolveUDPAddr("udp", net.JoinHostPort(os.Args[i+2], "443"))
			if err != nil {
				os.Exit(8)
			}
			connection, err := net.DialUDP("udp", local, remote)
			if err != nil {
				os.Exit(8)
			}
			_ = connection.SetWriteDeadline(time.Now().Add(time.Second))
			_, err = connection.Write([]byte("RAZVILKA isolated NFQUEUE native packet\n"))
			_ = connection.Close()
			if err != nil {
				os.Exit(8)
			}
			os.Exit(0)
		}
	}
	t.Skip("dedicated isolated native peer entry only")
}

func nfqwsScopedNativeCommand(t *testing.T, name string, args ...string) []byte {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	if err != nil {
		t.Fatalf("private netns command %s %v: %v: %s", name, args, err, out)
	}
	return out
}

func nfqwsScopedNativeCounter(t *testing.T, command, chain string) uint64 {
	t.Helper()
	out := nfqwsScopedNativeCommand(t, command, "-t", "mangle", "-L", chain, "-v", "-x", "-n")
	var count uint64
	for _, line := range strings.Split(string(out), "\n") {
		f := strings.Fields(line)
		if len(f) > 2 && f[2] == "NFQUEUE" {
			n, err := strconv.ParseUint(f[0], 10, 64)
			if err != nil {
				t.Fatal(err)
			}
			count += n
		}
	}
	return count
}

// ROOT-only real kernel harness. It does not claim the still pending common
// Execution registrar or production Start wiring. The test's guards own only
// its fixed disposable netns, reviewed process and exact compiled effects.
func TestNFQWSScopedKernelNative(t *testing.T) {
	if os.Getenv("RAZVILKA_NFQWS_SCOPED_NATIVE") != "1" {
		t.Skip("ROOT exclusive isolated kernel harness only")
	}
	program := nfqws2ManagedNativeGate(t)
	if os.Geteuid() != 0 {
		t.Fatal("ROOT required")
	}
	namespace, err := os.Readlink("/proc/self/ns/net")
	baseline, baseErr := os.Readlink("/proc/1/ns/net")
	if err != nil || baseErr != nil || namespace == baseline {
		t.Fatal("refusing a non-isolated network namespace")
	}
	for _, name := range []string{"ip", "iptables-legacy", "ip6tables-legacy", "nft", "unshare", "nsenter"} {
		if _, err := exec.LookPath(name); err != nil {
			t.Fatal("native capability prerequisite", name, err)
		}
	}
	tools := PolicyEffectTools{IP: "ip", IPTables: "iptables-legacy", IP6Tables: "ip6tables-legacy"}
	links := nfqwsScopedNativeCommand(t, "ip", "-o", "link", "show")
	for _, line := range strings.Split(strings.TrimSpace(string(links)), "\n") {
		if !strings.Contains(line, ": lo:") {
			t.Fatal("namespace has a preexisting interface", line)
		}
	}
	inputPath := os.Getenv("RAZVILKA_NFQWS_MANAGED_GENUINE_REVIEW")
	if inputPath == "" {
		t.Fatal("explicit pinned genuine byte review is mandatory")
	}
	var review struct {
		BinaryPath, BinarySHA256 string
		Assets                   []nfqws2ManagedFile
		BaseArguments            []string
	}
	data, err := os.ReadFile(inputPath)
	if err != nil || nfqws2ManagedUniqueJSON(data) != nil || json.Unmarshal(data, &review) != nil || len(review.BaseArguments) == 0 {
		t.Fatal("invalid pinned genuine review", err)
	}
	for _, arg := range review.BaseArguments {
		if !strings.HasPrefix(arg, "--lua-init=@") && !strings.HasPrefix(arg, "--blob=") {
			t.Fatal("review contains a non-data argument")
		}
	}
	private := t.TempDir()
	if os.Chmod(private, 0700) != nil {
		t.Fatal("private fixture root")
	}
	peerCtx, peerCancel := context.WithCancel(context.Background())
	peerReady := filepath.Join(private, "peer-ready")
	peer := exec.CommandContext(peerCtx, "unshare", "--net", program, "-test.run=^TestNFQWSScopedNativeEntry$", "nfqws-scoped-peer", peerReady)
	if err := peer.Start(); err != nil {
		peerCancel()
		t.Fatal(err)
	}
	defer func() { peerCancel(); _ = peer.Wait() }()
	deadline := time.Now().Add(3 * time.Second)
	for {
		if _, err := os.Stat(peerReady); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("private peer did not become ready")
		}
		time.Sleep(10 * time.Millisecond)
	}
	peerPID := strconv.Itoa(peer.Process.Pid)
	peerCommand := func(args ...string) []byte {
		return nfqwsScopedNativeCommand(t, "nsenter", append([]string{"-t", peerPID, "-n", "ip"}, args...)...)
	}
	nfqwsScopedNativeCommand(t, "ip", "link", "set", "lo", "up")
	nfqwsScopedNativeCommand(t, "ip", "link", "add", "br0", "type", "veth", "peer", "name", "peer0")
	nfqwsScopedNativeCommand(t, "ip", "link", "set", "peer0", "netns", peerPID)
	nfqwsScopedNativeCommand(t, "ip", "link", "set", "br0", "address", "02:00:00:00:00:10")
	nfqwsScopedNativeCommand(t, "ip", "link", "set", "br0", "up")
	nfqwsScopedNativeCommand(t, "ip", "addr", "add", "192.168.1.1/24", "dev", "br0")
	nfqwsScopedNativeCommand(t, "ip", "-6", "addr", "add", "fd00:1::1/64", "dev", "br0", "nodad")
	nfqwsScopedNativeCommand(t, "ip", "link", "add", "out0", "type", "dummy")
	nfqwsScopedNativeCommand(t, "ip", "link", "set", "out0", "up")
	nfqwsScopedNativeCommand(t, "ip", "route", "add", "8.8.8.8/32", "dev", "out0")
	nfqwsScopedNativeCommand(t, "ip", "-6", "route", "add", "2606:4700::/32", "dev", "out0")
	// These are namespace-local test forwarding switches, never host settings.
	for _, path := range []string{"/proc/sys/net/ipv4/ip_forward", "/proc/sys/net/ipv6/conf/all/forwarding"} {
		if err := os.WriteFile(path, []byte("1\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	peerCommand("link", "set", "lo", "up")
	peerCommand("link", "set", "peer0", "address", "02:00:00:00:00:02")
	peerCommand("link", "set", "peer0", "up")
	peerCommand("addr", "add", "192.168.1.2/24", "dev", "peer0")
	peerCommand("addr", "add", "192.168.1.77/24", "dev", "peer0")
	peerCommand("-6", "addr", "add", "fd00:1::2/64", "dev", "peer0", "nodad")
	peerCommand("-6", "addr", "add", "fd00:1::77/64", "dev", "peer0", "nodad")
	peerCommand("route", "add", "default", "via", "192.168.1.1")
	peerCommand("-6", "route", "add", "default", "via", "fd00:1::1")
	// Static private neighbors make the packet oracle independent of ARP/ND.
	peerCommand("neigh", "replace", "192.168.1.1", "lladdr", "02:00:00:00:00:10", "dev", "peer0", "nud", "permanent")
	peerCommand("-6", "neigh", "replace", "fd00:1::1", "lladdr", "02:00:00:00:00:10", "dev", "peer0", "nud", "permanent")
	plan, _, _ := nfqwsScopedFixture(t)
	lanRoot := filepath.Join(private, "lan")
	queueRoot := filepath.Join(private, "queue")
	for _, path := range []string{lanRoot, queueRoot} {
		if os.Mkdir(path, 0700) != nil {
			t.Fatal("private receipt root")
		}
	}
	runner := nfqws2ExecRunner{}
	lanRuntime := &LANPolicyRuntime{Runner: runner, IP: tools.IP, IPTables: tools.IPTables, IP6Tables: tools.IP6Tables, ScopeCheck: func(context.Context, *LANPolicyRuntimePlan) error { return nil }}
	lanBinding := &LANPolicyReceiptBinding{Runtime: lanRuntime, ApplyGuard: func(context.Context, *LANPolicyRuntimePlan, LANPolicyEffect) error { return nil }, CleanupGuard: func(context.Context, *LANPolicyRuntimePlan, LANPolicyEffect) error { return nil }, RetireCheck: func(context.Context, *LANPolicyRuntimePlan) error { return nil }}
	if err := lanBinding.Apply(context.Background(), plan.LAN, lanRoot); err != nil {
		t.Fatal("actual LAN gate", err)
	}
	a, command := nfqws2ManagedNativePrepare(t, program, strings.Repeat("6", 32), "hold")
	command.Program, command.Assets = nfqws2ManagedFile{review.BinaryPath, review.BinarySHA256}, review.Assets
	command.Args = append([]string{"--intercept=1", "--qnum=40321"}, review.BaseArguments...)
	command.Args = append(command.Args, "--filter-udp=443", "--lua-desync=fake:blob=0x00000000")
	command.Deadline = time.Now().Add(15 * time.Second).UTC()
	spec := NFQWSScopedSpec{Queue: 40321, BootID: command.Parent.BootID, NetNamespace: namespace, SessionID: command.ID, CommandSHA256: nfqws2ManagedCommandDigest(command), Candidate: NFQWSScopedCandidate{ID: "native-pinned-candidate", Incarnation: strings.Repeat("7", 32), ArgumentsSHA256: components.NFQWSRuntimeArgumentsSHA256(command.Program.Path, command.Args), Traffic: []NFQWSScopedTraffic{{Protocol: "udp", First: 443, Last: 443}}}}
	p, err := CompileNFQWSScopedPlan(plan, spec)
	if err != nil {
		t.Fatal(err)
	}
	b := &NFQWSScopedBinding{Runner: runner, Tools: tools,
		ApplyGuard: func(_ context.Context, got *NFQWSScopedPlan, _ PolicyEffect) error {
			if got != p {
				return ErrReviewChanged
			}
			return nil
		},
		CleanupGuard: func(_ context.Context, got *NFQWSScopedPlan, _ PolicyEffect) error {
			if got != p {
				return ErrReviewChanged
			}
			return nil
		},
		VerifyLAN: func(ctx context.Context, lan *LANPolicyRuntimePlan) error { return lanRuntime.Verify(ctx, lan) },
		ProcessRunning: func(ctx context.Context, p *NFQWSScopedPlan) (NFQWSScopedProcessProof, error) {
			return ReadNFQWSScopedManagedProcess(ctx, a, p, false)
		},
		ProcessInactive: func(ctx context.Context, p *NFQWSScopedPlan) (NFQWSScopedProcessProof, error) {
			return ReadNFQWSScopedManagedProcess(ctx, a, p, true)
		},
		QueueCheck: CheckNFQWSScopedQueue,
		AdditionalReadback: func(ctx context.Context, p *NFQWSScopedPlan) error {
			return CheckNFQWSScopedOtherBackends(ctx, runner, tools, "nft", p.resources.NetNamespace)
		}}
	lanRuntime.ConsumerCheck = func(ctx context.Context, _ *LANPolicyRuntimePlan) error { return b.CheckKnownReferences(ctx, p) }
	if err := b.CheckBeforeProcessStart(context.Background(), p); err != nil {
		t.Fatal("actual pre-start empty owner gate", err)
	}
	processCtx, processCancel := context.WithCancel(context.Background())
	defer processCancel()
	result := make(chan error, 1)
	go func() {
		_, err := a.runManagedNFQWSProcess(processCtx, command, []string{"-test.run=^TestNFQWSManagedProcessNativeEntry$", "nfqws-managed-helper"})
		result <- err
	}()
	settled := false
	defer func() {
		processCancel()
		if !settled {
			select {
			case <-result:
			case <-time.After(2 * time.Second):
				t.Error("managed process was not joined")
			}
		}
	}()
	deadline = time.Now().Add(3 * time.Second)
	for {
		if err := b.checkProcess(context.Background(), p, false); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("actual queue did not bind exact supervised child")
		}
		time.Sleep(10 * time.Millisecond)
	}
	proof, err := ReadNFQWSScopedManagedProcess(context.Background(), a, p, false)
	if err != nil {
		t.Fatal(err)
	}
	wrong := proof.Child
	wrong.Start = "1"
	if err := CheckNFQWSScopedQueue(context.Background(), namespace, spec.Queue, &wrong); err == nil {
		t.Fatal("wrong process birth adopted actual queue")
	}
	if err := b.VerifyPrepared(context.Background(), p, queueRoot); err != nil {
		t.Fatal("actual prepared closure", err)
	}
	if err := b.Apply(context.Background(), p, queueRoot); err != nil {
		t.Fatal("actual mixed NFQUEUE receipts", err)
	}
	send := func(source, target string) {
		nfqwsScopedNativeCommand(t, "nsenter", "-t", peerPID, "-n", program, "-test.run=^TestNFQWSScopedNativeEntry$", "nfqws-scoped-send", source, target)
		time.Sleep(40 * time.Millisecond)
	}
	for _, c := range p.chains {
		tool := tools.command(c.tool)
		before := nfqwsScopedNativeCounter(t, tool, c.name)
		if c.tool == PolicyEffectIPTables {
			send("192.168.1.2", "8.8.8.8")
		} else {
			send("fd00:1::2", "2606:4700::1")
		}
		if after := nfqwsScopedNativeCounter(t, tool, c.name); after <= before {
			t.Fatal("selected packet did not reach actual NFQUEUE", c.name, before, after)
		}
	}
	peerCommand("link", "set", "peer0", "address", "02:00:00:00:00:01")
	for _, c := range p.chains {
		tool := tools.command(c.tool)
		before := nfqwsScopedNativeCounter(t, tool, c.name)
		if c.tool == PolicyEffectIPTables {
			send("192.168.1.77", "8.8.8.8")
		} else {
			send("fd00:1::77", "2606:4700::1")
		}
		if after := nfqwsScopedNativeCounter(t, tool, c.name); after != before {
			t.Fatal("excluded MAC/new address entered actual NFQUEUE", c.name, before, after)
		}
	}
	processCancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatal("actual cancellation result", err)
		}
		settled = true
	case <-time.After(2 * time.Second):
		t.Fatal("actual managed process did not settle")
	}
	if err := b.Remove(context.Background(), p, queueRoot); err != nil {
		t.Fatal("actual receipt retirement", err)
	}
	before, err := os.ReadFile(filepath.Join(queueRoot, policyAdditionFile))
	if err != nil {
		t.Fatal(err)
	}
	nfqwsScopedNativeCommand(t, tools.IP6Tables, "-t", "raw", "-N", "FOREIGN_NATIVE")
	nfqwsScopedNativeCommand(t, tools.IP6Tables, "-t", "raw", "-A", "FOREIGN_NATIVE", "-j", "NFQUEUE", "--queue-num", "40321")
	if err := b.VerifyInactive(context.Background(), p, queueRoot); err == nil {
		t.Fatal("foreign IPv6 same queue cleared inactivity fence")
	}
	after, _ := os.ReadFile(filepath.Join(queueRoot, policyAdditionFile))
	if !bytes.Equal(before, after) {
		t.Fatal("foreign observation changed own receipt")
	}
	// Only ROOT's test fixture removes the exact rule it just created.
	nfqwsScopedNativeCommand(t, tools.IP6Tables, "-t", "raw", "-D", "FOREIGN_NATIVE", "-j", "NFQUEUE", "--queue-num", "40321")
	nfqwsScopedNativeCommand(t, tools.IP6Tables, "-t", "raw", "-X", "FOREIGN_NATIVE")
	if err := b.VerifyInactive(context.Background(), p, queueRoot); err != nil {
		t.Fatal("fresh actual inactivity", err)
	}
	lanRuntime.ConsumerCheck = nil
	lanBinding.RetireCheck = func(ctx context.Context, _ *LANPolicyRuntimePlan) error { return b.VerifyInactive(ctx, p, queueRoot) }
	if err := lanBinding.Remove(context.Background(), plan.LAN, lanRoot); err != nil {
		t.Fatal("LAN gate removed only after actual consumer retirement", err)
	}
	t.Log("actual pinned NFQUEUE socket owner; IPv4+IPv6 selected packets captured; excluded MAC/new addresses bypassed; exact process ECHILD+ACK; mixed receipts removed; foreign IPv6 refusal; LAN retired last. Common Execution wiring/health not claimed.")
}
