//go:build linux

package dataplane

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/components"
	"github.com/ArtixSx/razvilka/internal/operationgate"
)

// Fixture CLI runner consumes the accepted CORE control at the real Cmd.Start.
// It never puts probes, IPC or Wait inside the short control lock.
type nfqwsExecutionNativeRunner struct {
	control, installation string
	sequence              uint64
}

func (r nfqwsExecutionNativeRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	var output bytes.Buffer
	cmd.Stdout, cmd.Stderr = &output, &output
	err := operationgate.WithSelfUpdateEffectAdmission(ctx, r.control, strings.Repeat("4", 32), r.installation, r.sequence, "nfqws-paired-kernel", cmd.Start)
	if cmd.Process == nil {
		return output.Bytes(), fmt.Errorf("private kernel command admission %s %q: %w", name, args, err)
	}
	if err != nil {
		_ = cmd.Process.Kill()
	}
	waitErr := cmd.Wait()
	if failure := errors.Join(err, waitErr); failure != nil {
		data := output.Bytes()
		if len(data) > 1024 {
			data = data[:1024]
		}
		return output.Bytes(), fmt.Errorf("private kernel command %s %q (output=%q): %w", name, args, data, failure)
	}
	return output.Bytes(), nil
}

func TestNetworkPolicyManagerNFQWSNativePeerEntry(t *testing.T) {
	for i, arg := range os.Args {
		if arg == "nfqws-manager-paired-peer" {
			if os.Getenv("RAZVILKA_NFQWS_MANAGER_PAIRED_NATIVE") != "1" || len(os.Args[i:]) != 2 || os.WriteFile(os.Args[i+1], []byte("ready\n"), 0600) != nil {
				os.Exit(8)
			}
			time.Sleep(90 * time.Second)
			os.Exit(0)
		}
	}
	t.Skip("dedicated private paired peer entry only")
}

// ROOT-only pair of the actual common Manager issuer, managed Start bridge,
// exact execution process proof, NFQUEUE socket, LAN gate and mixed receipts.
// Review/WAN identity and the fixed private physical topology are fixture
// allowances. No production constructor, router or service health is claimed.
func TestNetworkPolicyManagerNFQWSPairedNative(t *testing.T) {
	if os.Getenv("RAZVILKA_NFQWS_MANAGER_PAIRED_NATIVE") != "1" {
		t.Skip("ROOT exclusive paired native harness only")
	}
	program := nfqws2ManagedNativeGate(t)
	namespace, err := os.Readlink("/proc/self/ns/net")
	baseline, baseErr := os.Readlink("/proc/1/ns/net")
	if os.Geteuid() != 0 || err != nil || baseErr != nil || namespace == baseline {
		t.Fatal("refusing a non-ROOT or non-isolated network namespace")
	}
	for _, name := range []string{"ip", "iptables-legacy", "ip6tables-legacy", "nft", "unshare", "nsenter"} {
		if _, err := exec.LookPath(name); err != nil {
			t.Fatal("native capability prerequisite", name, err)
		}
	}
	for _, line := range strings.Split(strings.TrimSpace(string(nfqwsScopedNativeCommand(t, "ip", "-o", "link", "show"))), "\n") {
		if !strings.Contains(line, ": lo:") {
			t.Fatal("namespace has a preexisting interface", line)
		}
	}
	var review struct {
		BinaryPath, BinarySHA256 string
		Assets                   []nfqws2ManagedFile
		BaseArguments            []string
	}
	data, err := os.ReadFile(os.Getenv("RAZVILKA_NFQWS_MANAGED_GENUINE_REVIEW"))
	if err != nil || nfqws2ManagedUniqueJSON(data) != nil || json.Unmarshal(data, &review) != nil || len(review.BaseArguments) == 0 {
		t.Fatal("explicit pinned genuine byte review is mandatory", err)
	}
	for _, arg := range review.BaseArguments {
		if !strings.HasPrefix(arg, "--lua-init=@") && !strings.HasPrefix(arg, "--blob=") {
			t.Fatal("review contains a non-data argument")
		}
	}
	private := t.TempDir()
	if err := os.Chmod(private, 0700); err != nil {
		t.Fatal(err)
	}
	peerCtx, peerCancel := context.WithCancel(context.Background())
	peerReady := filepath.Join(private, "peer-ready")
	peer := exec.CommandContext(peerCtx, "unshare", "--net", program, "-test.run=^TestNetworkPolicyManagerNFQWSNativePeerEntry$", "nfqws-manager-paired-peer", peerReady)
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
	for _, path := range []string{"/proc/sys/net/ipv4/ip_forward", "/proc/sys/net/ipv6/conf/all/forwarding"} {
		if err := os.WriteFile(path, []byte("1\n"), 0600); err != nil {
			t.Fatal(err) // Namespace-local fixture switches only.
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
	peerCommand("neigh", "replace", "192.168.1.1", "lladdr", "02:00:00:00:00:10", "dev", "peer0", "nud", "permanent")
	peerCommand("-6", "neigh", "replace", "fd00:1::1", "lladdr", "02:00:00:00:00:10", "dev", "peer0", "nud", "permanent")
	plan, _, _ := nfqwsScopedFixture(t)
	plan.NetworkProfileID, plan.Adapters = "wan-0123456789ab", []string{"nfqws2"}
	plan.Routes[0].NetworkPolicyRole = "override"
	encoded, _ := json.Marshal(plan)
	digest := sha256.Sum256(encoded)
	plan.Digest = hex.EncodeToString(digest[:])
	plan.PlanID = "dp-" + plan.Digest[:16]
	tools := PolicyEffectTools{IP: "ip", IPTables: "iptables-legacy", IP6Tables: "ip6tables-legacy"}
	controlRoot := filepath.Join(private, "shared-control")
	control, err := operationgate.InitializeSelfUpdateControl(context.Background(), controlRoot)
	if err != nil {
		t.Fatal(err)
	}
	runner := nfqwsExecutionNativeRunner{control: controlRoot, installation: control.InstallationID, sequence: control.Sequence}
	iface, err := net.InterfaceByName("br0")
	if err != nil {
		t.Fatal(err)
	}
	// Verify the actual fixture's namespace, link birth/index/MAC and addresses
	// on every LAN observation/effect; this is not production physical admission.
	physical := func(ctx context.Context, got *LANPolicyRuntimePlan) error {
		currentNS, err := os.Readlink("/proc/self/ns/net")
		current, linkErr := net.InterfaceByName("br0")
		if ctx.Err() != nil || err != nil || linkErr != nil || currentNS != namespace || current.Index != iface.Index || current.HardwareAddr.String() != "02:00:00:00:00:10" || !reflect.DeepEqual(got, plan.LAN) {
			return errors.Join(ErrLANPolicyRuntime, ctx.Err(), err, linkErr)
		}
		addrs, err := current.Addrs()
		if err != nil {
			return err
		}
		v4, v6 := false, false
		for _, addr := range addrs {
			v4 = v4 || addr.String() == "192.168.1.1/24"
			v6 = v6 || addr.String() == "fd00:1::1/64"
		}
		if !v4 || !v6 {
			return ErrLANPolicyRuntime
		}
		return ctx.Err()
	}
	lanRoot := filepath.Join(private, "lan")
	if err := os.Mkdir(lanRoot, 0700); err != nil {
		t.Fatal(err)
	}
	lanRuntime := &LANPolicyRuntime{Runner: runner, IP: tools.IP, IPTables: tools.IPTables, IP6Tables: tools.IP6Tables, ScopeCheck: physical}
	lanGuard := func(ctx context.Context, p *LANPolicyRuntimePlan, _ LANPolicyEffect) error { return physical(ctx, p) }
	lanBinding := &LANPolicyReceiptBinding{Runtime: lanRuntime, ApplyGuard: lanGuard, CleanupGuard: lanGuard, RetireCheck: physical}
	if err := lanBinding.Apply(context.Background(), plan.LAN, lanRoot); err != nil {
		t.Fatal("actual common LAN receipt", err)
	}
	var retired []*nfqwsExecutionAssembly
	retireLAN := func() {
		lanBinding.RetireCheck = func(ctx context.Context, p *LANPolicyRuntimePlan) error {
			if err := physical(ctx, p); err != nil {
				return err
			}
			for _, e := range retired {
				// Read-only post-scope observation, not a renewed writer grant:
				// existing mixed receipt plus SAME exact eight-field process
				// lease and whole queue/all-family capture absence.
				status, err := e.binding.Inspect(ctx, e.resource.Plan(), e.resource.Root())
				if err != nil || !status.Removed || status.Unknown || status.Promoted {
					return errors.Join(ErrNFQWSScopedOwner, err)
				}
				if err := e.binding.readback(ctx, e.resource.Plan(), nfqwsScopedAbsent, -1); err != nil {
					return err
				}
			}
			return ctx.Err()
		}
		if err := lanBinding.Remove(context.Background(), plan.LAN, lanRoot); err != nil {
			t.Fatal("LAN gate must retire last after exact paired consumer absence", err)
		}
	}
	var fencedManager *Manager
	for index, mode := range []string{"complete", "action-error", "cancel-after-capture", "late-start-current"} {
		if mode == "late-start-current" {
			retireLAN() // Complete owners first prove actual LAN-last removal.
			// A fresh fixture receipt exercises pending/no-start retention.
			// It does not adopt or reactivate any removed owner receipt.
			lanRoot = filepath.Join(private, "lan-pending-start")
			if err := os.Mkdir(lanRoot, 0700); err != nil {
				t.Fatal(err)
			}
			lanBinding.RetireCheck = physical
			if err := lanBinding.Apply(context.Background(), plan.LAN, lanRoot); err != nil {
				t.Fatal("fresh isolated LAN gate for pending case", err)
			}
		}
		if !t.Run(mode, func(t *testing.T) {
			peerCommand("link", "set", "peer0", "address", "02:00:00:00:00:02")
			a, command := nfqws2ManagedNativePrepare(t, program, strings.Repeat(strconv.Itoa(index+6), 32), "hold")
			command.ControlRoot, command.InstallationID, command.Sequence = controlRoot, control.InstallationID, control.Sequence
			command.Program, command.Assets = nfqws2ManagedFile{review.BinaryPath, review.BinarySHA256}, review.Assets
			queue := uint16(40321 + index)
			command.Args = append([]string{"--intercept=1", "--qnum=" + strconv.Itoa(int(queue))}, review.BaseArguments...)
			command.Args = append(command.Args, "--filter-udp=443", "--lua-desync=fake:blob=0x00000000")
			command.Deadline = time.Now().Add(15 * time.Second).UTC()
			spec := NFQWSScopedSpec{Queue: queue, BootID: command.Parent.BootID, NetNamespace: namespace, SessionID: command.ID, CommandSHA256: nfqws2ManagedCommandDigest(command), Candidate: NFQWSScopedCandidate{ID: "native-pinned-candidate", Incarnation: strings.Repeat(strconv.Itoa(index+6), 32), ArgumentsSHA256: components.NFQWSRuntimeArgumentsSHA256(command.Program.Path, command.Args), Traffic: []NFQWSScopedTraffic{{Protocol: "udp", First: 443, Last: 443}}}}
			m := New(filepath.Dir(filepath.Dir(a.StateRoot))) // Same actual adapter instance root.
			m.FreshProfile = func(c context.Context) (string, error) { return plan.NetworkProfileID, c.Err() }
			if err := m.Register(a); err != nil {
				t.Fatal(err)
			}
			if err := m.recordLocked(plan); err != nil {
				t.Fatal(err)
			}
			readExecution := func() (Execution, error) {
				var execution *Execution
				found, err := readOptionalJournal(filepath.Join(m.StateRoot, "latest-execution.json"), &execution)
				if err != nil || !found || execution == nil {
					return Execution{}, errors.Join(ErrExecutionJournal, err)
				}
				var transaction *Execution
				found, err = readOptionalJournal(filepath.Join(m.StateRoot, "transactions", execution.PlanID, "execution.json"), &transaction)
				if err != nil || !found || !reflect.DeepEqual(execution, transaction) {
					return Execution{}, errors.Join(ErrExecutionJournal, err)
				}
				return *execution, nil
			}
			var e *nfqwsExecutionAssembly
			intentObserved, armedDenied, actionCalled := false, false, false
			original, originalCancel := context.WithCancel(context.Background())
			defer originalCancel()
			ctx := WithReviewGuard(original, func(c context.Context) error {
				if err := c.Err(); err != nil {
					return err
				}
				data, err := os.ReadFile(filepath.Join(a.StateRoot, nfqws2LeaseFile))
				if errors.Is(err, os.ErrNotExist) {
					return nil
				}
				var lease nfqws2ManagedProcessLease
				if err != nil || json.Unmarshal(data, &lease) != nil || nfqws2ValidateManagedLease(lease) != nil || e == nil || lease.LaunchBinding == nil || *lease.LaunchBinding != e.resource.Binding() {
					return errors.Join(ErrNFQWSScopedOwner, err)
				}
				execution, err := readExecution()
				if err != nil || len(execution.Resources) != 1 || execution.ResourcePlanID != plan.PlanID || execution.PlanID != e.resource.Binding().ExecutionID {
					return errors.Join(ErrExecutionJournal, err)
				}
				resource := execution.Resources[0]
				if resource.NFQWS == nil {
					return ErrExecutionJournal
				}
				journalBinding := NFQWSExecutionBinding{ExecutionID: execution.PlanID, PlanID: execution.ResourcePlanID, PlanDigest: execution.Digest,
					ResourceID: resource.ID, ResourceGeneration: resource.Generation, EffectsDigest: resource.EffectsDigest,
					SessionID: resource.NFQWS.Spec.SessionID, CommandSHA256: resource.NFQWS.Spec.CommandSHA256}
				if journalBinding != *lease.LaunchBinding || journalBinding != e.resource.Binding() {
					return ErrExecutionJournal
				}
				if lease.Receipt.State == "intent" {
					intentObserved = true
					if execution.Resources[0].Phase != "process-pending" {
						return ErrExecutionJournal
					}
				}
				if mode == "late-start-current" && lease.Receipt.State == "armed" {
					armedDenied = true
					return ErrReviewChanged // Real READY, before single PERMIT/child Start.
				}
				return c.Err()
			})
			result := m.WithExecutionResources(ctx, plan, "nfqws2", func(borrowed context.Context) error {
				var err error
				e, err = newNFQWSExecutionAssembly(borrowed, a, command, spec, []string{"-test.run=^TestNFQWSManagedProcessNativeEntry$", "nfqws-managed-helper"}, nfqwsExecutionRuntime{Runner: runner, Tools: tools,
					VerifyLAN: lanRuntime.Verify,
					AdditionalReadback: func(c context.Context, p *NFQWSScopedPlan) error {
						if err := physical(c, p.lan); err != nil {
							return err
						}
						return CheckNFQWSScopedOtherBackends(c, runner, tools, "nft", namespace)
					}})
				if err != nil {
					return err
				}
				// Diagnostics run before the Prepared callback's deferred stop.
				// They never replace the actual owner result or grant readiness.
				processReadback := e.binding.ProcessRunning
				e.binding.ProcessRunning = func(c context.Context, p *NFQWSScopedPlan) (NFQWSScopedProcessProof, error) {
					proof, err := processReadback(c, p)
					if err != nil {
						nfqwsExecutionNativeReadinessDiagnostic(t, c, e, "running process", err)
					}
					return proof, err
				}
				queueReadback := e.binding.QueueCheck
				e.binding.QueueCheck = func(c context.Context, ns string, q uint16, child *components.NFQWSRuntimeProcessIdentity) error {
					err := queueReadback(c, ns, q, child)
					if err != nil && child == nil {
						nfqwsExecutionNativeReadinessDiagnostic(t, c, e, "whole empty queue", err)
					}
					return err
				}
				lanRuntime.ConsumerCheck = func(c context.Context, _ *LANPolicyRuntimePlan) error {
					return e.binding.CheckKnownReferences(c, e.resource.Plan())
				}
				return e.run(func(c context.Context, r *NFQWSExecutionResource, b *NFQWSScopedBinding) error {
					actionCalled = true
					execution, err := readExecution()
					if err != nil || execution.Resources[0].Phase != "capture-ready" {
						return errors.Join(ErrExecutionJournal, err)
					}
					proof, err := b.ProcessRunning(c, r.Plan())
					if err != nil || CheckNFQWSScopedQueue(c, namespace, queue, &proof.Child) != nil {
						return errors.Join(ErrNFQWSScopedOwner, err)
					}
					wrong := proof.Child
					wrong.Start = "1"
					if CheckNFQWSScopedQueue(c, namespace, queue, &wrong) == nil {
						return errors.New("foreign birth adopted exact queue")
					}
					if mode == "action-error" {
						return errors.New("paired action oracle failure")
					}
					if mode == "cancel-after-capture" {
						originalCancel()
						effects, _ := r.Plan().Effects()
						if r.Current(c, r.Binding()) == nil || r.ApplyGuard(c, r.Plan(), effects.Effects[0]) == nil {
							return errors.New("canceled current admitted another effect")
						}
						return nil
					}
					send := func(source, target string) {
						nfqwsScopedNativeCommand(t, "nsenter", "-t", peerPID, "-n", program, "-test.run=^TestNFQWSScopedNativeEntry$", "nfqws-scoped-send", source, target)
						time.Sleep(40 * time.Millisecond)
					}
					for _, chain := range r.Plan().chains {
						tool := tools.command(chain.tool)
						before := nfqwsScopedNativeCounter(t, tool, chain.name)
						if chain.tool == PolicyEffectIPTables {
							send("192.168.1.2", "8.8.8.8")
						} else {
							send("fd00:1::2", "2606:4700::1")
						}
						if after := nfqwsScopedNativeCounter(t, tool, chain.name); after <= before {
							return fmt.Errorf("selected packet missed actual queue %s: %d -> %d", chain.name, before, after)
						}
					}
					peerCommand("link", "set", "peer0", "address", "02:00:00:00:00:01")
					for _, chain := range r.Plan().chains {
						tool := tools.command(chain.tool)
						before := nfqwsScopedNativeCounter(t, tool, chain.name)
						if chain.tool == PolicyEffectIPTables {
							send("192.168.1.77", "8.8.8.8")
						} else {
							send("fd00:1::77", "2606:4700::1")
						}
						if after := nfqwsScopedNativeCounter(t, tool, chain.name); after != before {
							return fmt.Errorf("excluded MAC/new address entered queue %s: %d -> %d", chain.name, before, after)
						}
					}
					return nil
				})
			})
			lanRuntime.ConsumerCheck = nil
			if e == nil {
				t.Fatal("assembly did not acquire actual Manager resource", result)
			}
			if result != nil {
				status, inspectErr := e.binding.Inspect(context.Background(), e.resource.Plan(), e.resource.Root())
				t.Logf("paired checkpoint: action-called=%t intent-observed=%t armed-denied=%t receipt=%+v inspect-error=%v", actionCalled, intentObserved, armedDenied, status, inspectErr)
				if data, err := os.ReadFile(filepath.Join(e.resource.Root(), policyAdditionFile)); err == nil {
					var receipt policyAdditionDocument
					if json.Unmarshal(data, &receipt) == nil {
						states := make([]string, len(receipt.Steps))
						for i, step := range receipt.Steps {
							states[i] = strconv.Itoa(i) + ":" + step.State
						}
						t.Logf("paired receipt checkpoint: phase=%s steps=%v", receipt.Phase, states)
					}
				}
				for _, tool := range []string{tools.IPTables, tools.IP6Tables} {
					probe, cancel := context.WithTimeout(context.Background(), time.Second)
					data, err := runner.Run(probe, tool, "-t", "mangle", "-S")
					cancel()
					if len(data) > 4096 {
						data = data[:4096]
					}
					t.Logf("paired read-only mangle checkpoint: tool=%s error=%v rules=%s", tool, err, data)
				}
			}
			execution, err := readExecution()
			if err != nil || !intentObserved {
				t.Fatal("missing retained process-pending/intent pairing", result, err)
			}
			lease, err := a.observeManagedNFQWSProcessInactive(context.Background())
			if err != nil || !nfqwsScopedLeaseExecutionMatches(lease, e.resource.Plan(), e.resource.Binding()) || !lease.Receipt.WaitECHILD || !lease.Acknowledged {
				t.Fatal("same eight-field process did not finish ECHILD/parent ACK", err)
			}
			if mode == "late-start-current" {
				fencedManager = m
				if !errors.Is(result, ErrReviewChanged) || !armedDenied || actionCalled || lease.Receipt.Started || lease.Receipt.State != "not-started" || execution.State != "resource-failed" || execution.Resources[0].Phase != "closed" {
					t.Fatal("late Current did not fence before child Start", result, execution, lease.Receipt)
				}
				if _, err := os.Stat(filepath.Join(e.resource.Root(), policyAdditionFile)); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("late Start refusal wrote capture receipt", err)
				}
				if err := e.binding.readback(context.Background(), e.resource.Plan(), nfqwsScopedBeforeStart, -1); err != nil {
					t.Fatal("late Start refusal changed queue/LAN/capture", err)
				}
				if err := New(m.StateRoot).CheckExecutionRecovery(context.Background()); !errors.Is(err, ErrExecutionJournal) {
					t.Fatal("not-started process fabricated unused resource", err)
				}
			} else {
				if !actionCalled || execution.State != "temporary-complete" || execution.Resources[0].State != "removed" || execution.Resources[0].Phase != "removed" {
					t.Fatal("actual capture did not retire both common journals", result, execution)
				}
				if mode == "complete" && result != nil || mode == "action-error" && (result == nil || !strings.Contains(result.Error(), "paired action oracle failure")) || mode == "cancel-after-capture" && !errors.Is(result, context.Canceled) {
					t.Fatal("action/cancellation result was incorrectly normalized", result)
				}
				if err := New(m.StateRoot).CheckExecutionRecovery(context.Background()); err != nil {
					t.Fatal("removed exact owner retained false recovery fence", err)
				}
				retired = append(retired, e)
			}
			if e.resource.Current(context.Background(), e.resource.Binding()) == nil {
				t.Fatal("borrowed Current survived common scope close")
			}
			before, err := os.ReadFile(filepath.Join(a.StateRoot, nfqws2LeaseFile))
			if err != nil {
				t.Fatal(err)
			}
			if e.run(func(context.Context, *NFQWSExecutionResource, *NFQWSScopedBinding) error { return nil }) == nil {
				t.Fatal("closed managed invocation replayed")
			}
			after, _ := os.ReadFile(filepath.Join(a.StateRoot, nfqws2LeaseFile))
			if !bytes.Equal(before, after) {
				t.Fatal("closed invocation changed actual process receipt")
			}
		}) {
			return // Preserve failed fixture evidence; no later consumer or LAN removal.
		}
	}
	if fencedManager == nil {
		t.Fatal("missing pending-start fence")
	}
	lanBinding.RetireCheck = func(ctx context.Context, _ *LANPolicyRuntimePlan) error {
		return fencedManager.CheckExecutionRecovery(ctx)
	}
	before, err := os.ReadFile(filepath.Join(lanRoot, policyAdditionFile))
	if err != nil {
		t.Fatal(err)
	}
	if err := lanBinding.Remove(context.Background(), plan.LAN, lanRoot); !errors.Is(err, ErrExecutionJournal) {
		t.Fatal("pending resource allowed LAN retirement", err)
	}
	after, _ := os.ReadFile(filepath.Join(lanRoot, policyAdditionFile))
	if !bytes.Equal(before, after) || lanRuntime.Verify(context.Background(), plan.LAN) != nil {
		t.Fatal("pending-start fence did not retain whole LAN gate/receipt")
	}
	t.Log("real Manager/Start/queue/LAN/receipt pair: same eight fields, pending before intent, selected v4/v6 and excluded MAC/new addresses, closing Current, exact ECHILD+ACK, known cleanup after action failure/cancel, LAN last after removed owners; fresh pending READY denial without child/capture keeps resource fence and LAN, no replay/unused adoption")
}

// Read-only failure evidence, sampled while the same managed child is still
// live. A single image is diagnostic only; the real double observer remains
// the only proof used by the binding.
func nfqwsExecutionNativeReadinessDiagnostic(t *testing.T, ctx context.Context, e *nfqwsExecutionAssembly, stage string, primary error) {
	t.Helper()
	t.Logf("paired live readiness checkpoint: stage=%s error=%v", stage, primary)
	data, readErr := os.ReadFile(filepath.Join(e.adapter.StateRoot, nfqws2LeaseFile))
	var lease nfqws2ManagedProcessLease
	if readErr == nil && len(data) <= 1<<20 && json.Unmarshal(data, &lease) == nil {
		proof := NFQWSScopedProcessProof{SessionID: lease.Command.ID, CommandSHA256: lease.CommandSHA256, Receipt: lease.Receipt, Child: lease.Child, Acknowledged: lease.Acknowledged}
		actual, identityErr := components.ReadNFQWSRuntimeProcessIdentity(lease.Child.PID)
		childNS, namespaceErr := os.Readlink(fmt.Sprintf("/proc/%d/ns/net", lease.Child.PID))
		t.Logf("paired live lease checkpoint: state=%s acknowledged=%t valid=%v binding-matches=%t command-args-match=%t proof-shape=%v child-matches=%t identity-error=%v namespace-matches=%t namespace-error=%v",
			lease.Receipt.State, lease.Acknowledged, nfqws2ValidateManagedLease(lease), nfqwsScopedLeaseExecutionMatches(lease, e.resource.Plan(), e.resource.Binding()),
			components.NFQWSRuntimeArgumentsSHA256(lease.Command.Program.Path, lease.Command.Args) == e.resource.Plan().resources.ArgumentsHash,
			nfqwsScopedProcessProof(e.resource.Plan(), proof, false), actual == lease.Child, identityErr, childNS == e.resource.Plan().resources.NetNamespace, namespaceErr)
	} else {
		t.Logf("paired live lease checkpoint: read-error=%v bytes=%d", readErr, len(data))
	}
	for _, path := range []string{"/proc/net/netfilter/nfnetlink_queue", "/proc/net/netlink"} {
		out, err := nfqwsScopedReadProc(ctx, path)
		if path == "/proc/net/netlink" {
			var netfilter []string
			for _, line := range strings.Split(out, "\n") {
				fields := strings.Fields(line)
				if len(fields) == 10 && (fields[0] == "sk" || fields[1] == "12") {
					netfilter = append(netfilter, line)
				}
			}
			out = strings.Join(netfilter, "\n")
		}
		if len(out) > 4096 {
			out = out[:4096]
		}
		t.Logf("paired live queue checkpoint: path=%s error=%v output=%s", path, err, out)
	}
}
