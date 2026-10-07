package dataplane

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/netidentity"
)

const scopedDNSInactiveSocketHeader = "sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n"

type scopedDNSInactiveFixture struct {
	a           *ScopedDNSAdapter
	m           *Manager
	in          Input
	proof       scopedDNSInactiveProof
	kernelCalls int
}

func newScopedDNSInactiveFixture(t *testing.T) *scopedDNSInactiveFixture {
	t.Helper()
	m, a, _, in := scopedAdapterFixture(t)
	a.StateRoot = filepath.Join(m.StateRoot, scopedDNSAdapterID)
	if err := os.MkdirAll(m.StateRoot, 0700); err != nil {
		t.Fatal(err)
	}
	proc := t.TempDir()
	f := &scopedDNSInactiveFixture{a: a, m: m, in: in}
	f.proof = scopedDNSInactiveProof{procRoot: proc, netRoot: filepath.Join(proc, "net"), selfPID: 101}
	f.proof.sameExecutable = func(string, string) (bool, error) { return false, nil }
	f.proof.readlink = func(path string) (string, error) {
		if strings.Contains(path, string(filepath.Separator)+"102"+string(filepath.Separator)) {
			return "/opt/bin/other", nil
		}
		return "/opt/bin/razvilka", nil
	}
	f.proof.withCurrent = func(ctx context.Context, use func(context.Context, netidentity.Identity) error) error {
		return use(ctx, netidentity.Identity{Version: 1, Kind: netidentity.ProcNetInode, BootID: "11111111-2222-3333-4444-555555555555", Inode: 123})
	}
	a.InactivityKernelCheck = func(ctx context.Context, identity netidentity.Identity) error {
		f.kernelCalls++
		return errors.Join(ctx.Err(), identity.Validate())
	}
	f.process(t, 101, "razvilka")
	if err := os.MkdirAll(f.proof.netRoot, 0700); err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"tcp", "tcp6", "udp", "udp6"} {
		f.socket(t, kind, "")
	}
	return f
}

func (f *scopedDNSInactiveFixture) process(t *testing.T, pid int, command string) {
	t.Helper()
	root := filepath.Join(f.proof.procRoot, strconv.Itoa(pid))
	if err := os.MkdirAll(root, 0700); err != nil {
		t.Fatal(err)
	}
	fields := make([]string, 20)
	for i := range fields {
		fields[i] = "0"
	}
	fields[0], fields[19] = "S", "17"
	writeDNSInactiveFixture(t, filepath.Join(root, "stat"), []byte(fmt.Sprintf("%d (%s) %s", pid, command, strings.Join(fields, " "))))
	writeDNSInactiveFixture(t, filepath.Join(root, "cmdline"), []byte(command+"\x00"))
}

func (f *scopedDNSInactiveFixture) socket(t *testing.T, kind, row string) {
	t.Helper()
	writeDNSInactiveFixture(t, filepath.Join(f.proof.netRoot, kind), []byte(scopedDNSInactiveSocketHeader+row))
}

func writeDNSInactiveFixture(t *testing.T, path string, raw []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
}

func (f *scopedDNSInactiveFixture) applyStop(t *testing.T, suspend bool) {
	t.Helper()
	p, err := Build(f.in)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.m.Apply(context.Background(), p, nil); err != nil {
		t.Fatal(err)
	}
	if suspend {
		in := f.in
		in.Revision++
		in.DNS, in.Routes = nil, nil
		in.RetiringAdapters, in.SuspendDNS = []string{f.a.ID()}, true
		stop, err := Build(in)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.m.Apply(context.Background(), stop, nil); err != nil {
			t.Fatal(err)
		}
	} else if err := f.a.Deactivate(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func (f *scopedDNSInactiveFixture) verify() error {
	return f.a.verifyDNSRuntimeInactive(context.Background(), f.proof)
}

func TestScopedDNSInactiveColdAndStopped(t *testing.T) {
	for _, mode := range []string{"first-use", "committed-deactivated", "suspended", "discarded"} {
		t.Run(mode, func(t *testing.T) {
			f := newScopedDNSInactiveFixture(t)
			if mode != "first-use" {
				f.applyStop(t, mode == "suspended" || mode == "discarded")
			}
			if mode == "discarded" {
				in := f.in
				in.Revision++
				in.DNS, in.Routes = nil, nil
				in.RetiringAdapters, in.DiscardDNS = []string{f.a.ID()}, true
				p, err := Build(in)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := f.m.Apply(context.Background(), p, nil); err != nil {
					t.Fatal(err)
				}
			}
			// The cold observer has neither DNS activation manager nor live pointer.
			cold := NewScopedDNSAdapter(context.Background(), nil, f.m.StateRoot)
			cold.InactivitySettingsPath, cold.InactivityKernelCheck = f.a.InactivitySettingsPath, f.a.InactivityKernelCheck
			f.a = cold
			before := dnsInactiveDisk(t, f.m.StateRoot)
			if err := f.verify(); err != nil {
				t.Fatal(err)
			}
			if f.kernelCalls != 1 || !reflect.DeepEqual(before, dnsInactiveDisk(t, f.m.StateRoot)) {
				t.Fatal("observer mutated files or skipped mandatory kernel consumer")
			}
		})
	}
}

func dnsInactiveDisk(t *testing.T, root string) map[string]string {
	t.Helper()
	result := make(map[string]string)
	if err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		raw, err := os.ReadFile(path)
		result[path] = string(raw)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return result
}

func TestScopedDNSInactiveRejectsUnknownDependenciesAndSavedState(t *testing.T) {
	cases := map[string]func(*testing.T, *scopedDNSInactiveFixture){
		"missing-settings": func(t *testing.T, f *scopedDNSInactiveFixture) {
			if err := os.Remove(f.a.InactivitySettingsPath); err != nil {
				t.Fatal(err)
			}
		},
		"nil-kernel": func(_ *testing.T, f *scopedDNSInactiveFixture) { f.a.InactivityKernelCheck = nil },
		"unknown-coverage": func(_ *testing.T, f *scopedDNSInactiveFixture) {
			f.a.InactivityKernelCheck = func(context.Context, netidentity.Identity) error { return errBackendInventory }
		},
		"nil-identity": func(_ *testing.T, f *scopedDNSInactiveFixture) { f.proof.withCurrent = nil },
		"old-schema": func(t *testing.T, f *scopedDNSInactiveFixture) {
			raw, _ := os.ReadFile(f.a.InactivitySettingsPath)
			writeDNSInactiveFixture(t, f.a.InactivitySettingsPath, []byte(strings.Replace(string(raw), `"schema": 5`, `"schema": 4`, 1)))
		},
		"duplicate-field": func(t *testing.T, f *scopedDNSInactiveFixture) {
			raw, _ := os.ReadFile(f.a.InactivitySettingsPath)
			writeDNSInactiveFixture(t, f.a.InactivitySettingsPath, []byte(strings.Replace(string(raw), `"schema": 5`, `"schema": 5,"schema": 5`, 1)))
		},
		"foreign-field": func(t *testing.T, f *scopedDNSInactiveFixture) {
			raw, _ := os.ReadFile(f.a.InactivitySettingsPath)
			writeDNSInactiveFixture(t, f.a.InactivitySettingsPath, append([]byte(`{"foreign":true,`), raw[1:]...))
		},
		"retained-selection-without-plan": func(t *testing.T, f *scopedDNSInactiveFixture) {
			review, err := f.a.DNS.ReviewServiceSelection("web", "private")
			if err != nil {
				t.Fatal(err)
			}
			if err := f.a.DNS.CommitServiceSelection(review); err != nil {
				t.Fatal(err)
			}
		},
		"unknown-owner": func(t *testing.T, f *scopedDNSInactiveFixture) {
			writeDNSInactiveFixture(t, f.a.statePath(), []byte(`{"legacy":true}`))
		},
		"pending-file": func(t *testing.T, f *scopedDNSInactiveFixture) {
			writeDNSInactiveFixture(t, filepath.Join(f.a.StateRoot, ".transaction-pending"), []byte("pending"))
		},
		"pending-execution": func(t *testing.T, f *scopedDNSInactiveFixture) {
			writeDNSInactiveFixture(t, filepath.Join(f.m.StateRoot, "latest-execution.json"), []byte(`{"state":"committing"}`))
		},
		"malformed-socket": func(t *testing.T, f *scopedDNSInactiveFixture) { f.socket(t, "udp6", "malformed\n") },
		"missing-socket-family": func(t *testing.T, f *scopedDNSInactiveFixture) {
			if err := os.Remove(filepath.Join(f.proof.netRoot, "udp6")); err != nil {
				t.Fatal(err)
			}
		},
		"foreign-controller": func(t *testing.T, f *scopedDNSInactiveFixture) { f.process(t, 102, "razvilka") },
		"foreign-ownership-argument": func(t *testing.T, f *scopedDNSInactiveFixture) {
			f.process(t, 102, "other")
			writeDNSInactiveFixture(t, filepath.Join(f.proof.procRoot, "102", "cmdline"), []byte("other\x00--dns-state="+f.a.InactivitySettingsPath+"\x00"))
		},
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			f := newScopedDNSInactiveFixture(t)
			change(t, f)
			if err := f.verify(); !errors.Is(err, ErrScopedDNSRuntimeInactive) {
				t.Fatalf("accepted unknown state: %v", err)
			}
		})
	}
}

func TestScopedDNSInactiveKernelPredicate(t *testing.T) {
	for _, family := range []int{4, 6} {
		for _, row := range [][]string{{"-N", "RZD_orphan"}, {"-A", "INPUT", "-j", "RZD_orphan"}, {"-A", "INPUT", "--goto", "RZD_orphan"}, {"-A", "FOREIGN", "--unknown", "RZD_orphan"}} {
			if err := CheckScopedDNSInactiveRule(family, "custom", row); err == nil {
				t.Fatalf("accepted attachment %v", row)
			}
		}
		if err := CheckScopedDNSInactiveRule(family, "nat", []string{"-A", "INPUT", "-m", "comment", "--comment", "RZD_literal", "-j", "RETURN"}); err != nil {
			t.Fatal(err)
		}
	}
}

func TestScopedDNSInactiveRetainedPortsEverySocketFamily(t *testing.T) {
	for _, kind := range []string{"tcp", "tcp6", "udp", "udp6"} {
		t.Run(kind, func(t *testing.T) {
			f := newScopedDNSInactiveFixture(t)
			f.applyStop(t, false)
			addr := "00000000"
			if strings.HasSuffix(kind, "6") {
				addr = strings.Repeat("0", 32)
			}
			state := "0A"
			if strings.HasPrefix(kind, "udp") {
				state = "07"
			}
			f.socket(t, kind, "0: "+addr+":2939 "+addr+":0000 "+state+" 00000000:00000000 00:00000000 00000000 0 0 99\n")
			if err := f.verify(); err == nil || f.kernelCalls != 0 {
				t.Fatalf("owned listener accepted: %v", err)
			}
		})
	}
}

func TestScopedDNSInactiveDiscardStillChecksRetiredPort(t *testing.T) {
	f := newScopedDNSInactiveFixture(t)
	f.applyStop(t, true)
	in := f.in
	in.Revision += 2
	in.DNS, in.Routes = nil, nil
	in.RetiringAdapters, in.DiscardDNS = []string{f.a.ID()}, true
	p, err := Build(in)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.m.Apply(context.Background(), p, nil); err != nil {
		t.Fatal(err)
	}
	if err := f.verify(); err != nil {
		t.Fatal(err)
	}
	f.socket(t, "udp6", "0: "+strings.Repeat("0", 32)+":2939 "+strings.Repeat("0", 32)+":0000 07 00000000:00000000 00:00000000 00000000 0 0 99\n")
	if err := f.verify(); err == nil {
		t.Fatal("discard erased negative socket scope")
	}
}

func TestScopedDNSInactiveLateDriftAndCancel(t *testing.T) {
	for _, kind := range []string{"settings", "process", "socket", "lifecycle-ABA", "restart-stop-ABA", "cancel", "identity", "closing-identity-file", "closing-identity-lifecycle"} {
		t.Run(kind, func(t *testing.T) {
			f := newScopedDNSInactiveFixture(t)
			f.applyStop(t, false)
			ctx, cancel := context.WithCancel(context.WithValue(context.Background(), scopedDNSInactiveTestKey{}, "preserved"))
			defer cancel()
			f.a.InactivityKernelCheck = func(c context.Context, _ netidentity.Identity) error {
				if c.Value(scopedDNSInactiveTestKey{}) != "preserved" {
					t.Fatal("caller values lost")
				}
				switch kind {
				case "settings":
					raw, _ := os.ReadFile(f.a.InactivitySettingsPath)
					writeDNSInactiveFixture(t, f.a.InactivitySettingsPath, append(raw, '\n'))
				case "process":
					f.process(t, 102, "razvilka")
				case "socket":
					f.socket(t, "udp", "0: 00000000:2939 00000000:0000 07 00000000:00000000 00:00000000 00000000 0 0 99\n")
				case "lifecycle-ABA":
					done := scopedDNSInactiveMutation(f.a.StateRoot)
					done()
				case "restart-stop-ABA":
					plan, _, err := f.m.Committed()
					if err != nil {
						t.Fatal(err)
					}
					candidate := t.TempDir()
					if err := f.a.Stage(c, plan, candidate); err != nil {
						t.Fatal(err)
					}
					if err := f.a.Activate(c, plan, candidate); err != nil {
						t.Fatal(err)
					}
					if err := f.a.Deactivate(c); err != nil {
						t.Fatal(err)
					}
				case "cancel":
					cancel()
				}
				return nil
			}
			if kind == "identity" || strings.HasPrefix(kind, "closing-identity-") {
				old := f.proof.withCurrent
				f.proof.withCurrent = func(c context.Context, use func(context.Context, netidentity.Identity) error) error {
					if err := old(c, use); err != nil {
						return err
					}
					switch kind {
					case "identity":
						return netidentity.ErrUnknown
					case "closing-identity-file":
						raw, _ := os.ReadFile(f.a.InactivitySettingsPath)
						writeDNSInactiveFixture(t, f.a.InactivitySettingsPath, append(raw, '\n'))
					case "closing-identity-lifecycle":
						finish := scopedDNSInactiveMutation(f.a.StateRoot)
						finish()
					}
					return nil
				}
			}
			if err := f.a.verifyDNSRuntimeInactive(ctx, f.proof); err == nil {
				t.Fatal("accepted late drift")
			}
		})
	}
}

type scopedDNSInactiveTestKey struct{}

func TestScopedDNSInactiveLifecycleMissingOwnerAndJoin(t *testing.T) {
	f := newScopedDNSInactiveFixture(t)
	p, err := Build(f.in)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.m.Apply(context.Background(), p, nil); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(f.a.statePath()); err != nil {
		t.Fatal(err)
	}
	cold := NewScopedDNSAdapter(context.Background(), nil, f.m.StateRoot)
	cold.InactivitySettingsPath, cold.InactivityKernelCheck = f.a.InactivitySettingsPath, f.a.InactivityKernelCheck
	if err := cold.verifyDNSRuntimeInactive(context.Background(), f.proof); err == nil || f.kernelCalls != 0 {
		t.Fatal("cold nil live promoted over active session without owner")
	}
	if err := f.a.Deactivate(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := cold.verifyDNSRuntimeInactive(context.Background(), f.proof); err != nil {
		t.Fatal(err)
	}
}

func TestScopedDNSInactiveSessionNeedsCancelJoinAndClosedSockets(t *testing.T) {
	udp, tcp, err := listenScopedDNS(netip.MustParseAddrPort("127.0.0.1:0"))
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	defer tcp.Close()
	s := &scopedDNSSession{done: make(chan struct{}), resources: scopedDNSInactiveResources{udp: udp, tcp: tcp}}
	s.resources.cancelled.Store(true)
	if err := s.inactiveJoined(); err == nil {
		t.Fatal("accepted unjoined worker")
	}
	close(s.done)
	if err := s.inactiveJoined(); err == nil {
		t.Fatal("accepted open sockets after done")
	}
	_ = udp.Close()
	_ = tcp.Close()
	if err := s.inactiveJoined(); err != nil {
		t.Fatal(err)
	}
	s.resources.cancelled.Store(false)
	if err := s.inactiveJoined(); err == nil {
		t.Fatal("accepted absent cancellation")
	}
}

func TestScopedDNSInactiveDeadlineAndReadOnlyFailure(t *testing.T) {
	f := newScopedDNSInactiveFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Millisecond)
	defer cancel()
	f.a.InactivityKernelCheck = func(c context.Context, _ netidentity.Identity) error { <-c.Done(); return c.Err() }
	before := dnsInactiveDisk(t, f.m.StateRoot)
	if err := f.a.verifyDNSRuntimeInactive(ctx, f.proof); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, dnsInactiveDisk(t, f.m.StateRoot)) {
		t.Fatal("failed observer mutated disk")
	}
	if err := f.a.VerifyRuntimeInactive(context.Background()); err == nil {
		t.Fatal("production accepted missing typed provider")
	}
}

func TestScopedDNSInactiveStrictImagesAndIncarnations(t *testing.T) {
	for _, kind := range []string{"oversized-settings", "invalid-selection", "pending-settings", "orphan-transactions", "pending-publication", "legacy-committed", "paired-outcome", "renamed-controller", "exe-drift", "argv-drift", "warm-path-mismatch", "reserved-compact-target"} {
		t.Run(kind, func(t *testing.T) {
			f := newScopedDNSInactiveFixture(t)
			switch kind {
			case "oversized-settings":
				writeDNSInactiveFixture(t, f.a.InactivitySettingsPath, []byte(strings.Repeat(" ", (128<<10)+1)))
			case "invalid-selection":
				raw, _ := os.ReadFile(f.a.InactivitySettingsPath)
				writeDNSInactiveFixture(t, f.a.InactivitySettingsPath, []byte(strings.ReplaceAll(string(raw), "automatic", "foreign-profile")))
			case "pending-settings":
				writeDNSInactiveFixture(t, filepath.Join(filepath.Dir(f.a.InactivitySettingsPath), ".dns-pending.tmp"), []byte("pending"))
			case "orphan-transactions":
				writeDNSInactiveFixture(t, filepath.Join(f.m.StateRoot, "transactions", "old", "candidate.json"), []byte("orphan"))
			case "pending-publication":
				writeDNSInactiveFixture(t, filepath.Join(f.m.StateRoot, ".transaction-pending"), []byte("pending"))
			case "legacy-committed":
				f.applyStop(t, false)
				if err := os.Remove(filepath.Join(f.m.StateRoot, "latest-committed-plan.json")); err != nil {
					t.Fatal(err)
				}
			case "paired-outcome":
				f.applyStop(t, false)
				raw, _ := os.ReadFile(filepath.Join(f.m.StateRoot, "latest-execution.json"))
				var e Execution
				if err := json.Unmarshal(raw, &e); err != nil {
					t.Fatal(err)
				}
				e.State = "rolled-back"
				changed, _ := json.Marshal(e)
				writeDNSInactiveFixture(t, filepath.Join(f.m.StateRoot, "transactions", e.PlanID, "execution.json"), changed)
			case "renamed-controller":
				f.process(t, 102, "other")
				f.proof.sameExecutable = func(string, string) (bool, error) { return true, nil }
			case "exe-drift":
				f.process(t, 102, "other")
				old := f.proof.readlink
				calls := 0
				f.proof.readlink = func(path string) (string, error) {
					if strings.Contains(path, string(filepath.Separator)+"102"+string(filepath.Separator)) {
						calls++
						if calls > 1 {
							return "/opt/bin/changed", nil
						}
					}
					return old(path)
				}
			case "argv-drift":
				f.process(t, 102, "other")
				f.proof.sameExecutable = func(string, string) (bool, error) {
					writeDNSInactiveFixture(t, filepath.Join(f.proof.procRoot, "102", "cmdline"), []byte("changed\x00"))
					return false, nil
				}
			case "warm-path-mismatch":
				f.a.InactivitySettingsPath = filepath.Join(filepath.Dir(f.a.InactivitySettingsPath), "different.json")
			case "reserved-compact-target":
				f.a.InactivityKernelCheck = func(context.Context, netidentity.Identity) error {
					return CheckScopedDNSInactiveRule(6, "custom", []string{"-A", "INPUT", "--jump=RZD_orphan"})
				}
			}
			if err := f.verify(); err == nil {
				t.Fatal("accepted unknown/drifting image")
			}
		})
	}
}

func TestScopedDNSInactiveProtectedPaths(t *testing.T) {
	for _, kind := range []string{"settings-symlink", "runtime-symlink", "writable-file"} {
		t.Run(kind, func(t *testing.T) {
			f := newScopedDNSInactiveFixture(t)
			if kind == "writable-file" {
				if runtime.GOOS != "linux" {
					t.Skip("actual permission semantics belong to Root Linux run")
				}
				if err := os.Chmod(f.a.InactivitySettingsPath, 0644); err != nil {
					t.Fatal(err)
				}
			} else {
				path := f.a.StateRoot
				target := t.TempDir()
				if kind == "settings-symlink" {
					path = f.a.InactivitySettingsPath
					raw, _ := os.ReadFile(path)
					target = filepath.Join(target, "settings.json")
					writeDNSInactiveFixture(t, target, raw)
					if err := os.Remove(path); err != nil {
						t.Fatal(err)
					}
				}
				if err := os.Symlink(target, path); err != nil {
					t.Skipf("fixture symlink unsupported: %v", err)
				}
			}
			if err := f.verify(); err == nil {
				t.Fatal("accepted unprotected file scope")
			}
		})
	}
}

func TestScopedDNSInactiveColdSeesStartBeforeOwnerPublication(t *testing.T) {
	f := newScopedDNSInactiveFixture(t)
	entered, release, result := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
	}()
	f.a.listen = func(netip.AddrPort) (*net.UDPConn, *net.TCPListener, error) {
		close(entered)
		<-release
		return nil, nil, context.Canceled
	}
	p, err := Build(f.in)
	if err != nil {
		t.Fatal(err)
	}
	candidate := t.TempDir()
	if err := f.a.Stage(context.Background(), p, candidate); err != nil {
		t.Fatal(err)
	}
	go func() { result <- f.a.Activate(context.Background(), p, candidate) }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("start did not reach listener seam")
	}
	cold := NewScopedDNSAdapter(context.Background(), nil, f.m.StateRoot)
	cold.InactivitySettingsPath, cold.InactivityKernelCheck = f.a.InactivitySettingsPath, f.a.InactivityKernelCheck
	err = cold.verifyDNSRuntimeInactive(context.Background(), f.proof)
	close(release)
	if stopped := <-result; !errors.Is(stopped, context.Canceled) {
		t.Fatal(stopped)
	}
	if err == nil || f.kernelCalls != 0 {
		t.Fatal("accepted in-flight start with missing owner")
	}
	if err := cold.verifyDNSRuntimeInactive(context.Background(), f.proof); err != nil {
		t.Fatal(err)
	}
}

func TestScopedDNSInactiveServeEarlyFailureClosesSockets(t *testing.T) {
	f := newScopedDNSInactiveFixture(t)
	u, tcp, err := f.a.listen(netip.AddrPort{})
	if err != nil {
		t.Fatal(err)
	}
	defer u.Close()
	defer tcp.Close()
	s := &scopedDNSSession{done: make(chan struct{}), resources: scopedDNSInactiveResources{udp: u, tcp: tcp}}
	s.resources.cancelled.Store(true)
	go s.serve(context.Background()) // nil resolver's early refusal precedes its close/join loop.
	select {
	case <-s.done:
	case <-time.After(time.Second):
		t.Fatal("early refusal did not complete")
	}
	if err := s.inactiveJoined(); err != nil {
		t.Fatal("early Serve refusal leaked sockets", err)
	}
}
