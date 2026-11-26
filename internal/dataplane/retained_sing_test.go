package dataplane

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/engineconfig"
	"github.com/ArtixSx/razvilka/internal/routeidentity"
)

// Real Manager/Proxy transaction, private files and policy journals; only the
// process/kernel/service IO is modeled. No installed engine or network is used.
type retainedSingModelProcesses struct {
	*proxyFakeProcesses
	birth int
	boot  string
	live  map[string]routeidentity.Receipt
}

func (p *retainedSingModelProcesses) Start(ctx context.Context, spec ProcessSpec) error {
	if err := p.proxyFakeProcesses.Start(ctx, spec); err != nil {
		return err
	}
	p.birth++
	data, err := os.ReadFile(spec.MatchArg)
	if err != nil {
		return err
	}
	receipt := routeidentity.Receipt{Version: 1, PID: 100 + p.birth, BootID: p.boot, StartTicks: strconv.Itoa(p.birth), Executable: spec.Binary,
		ArgsHash: routeidentity.Hash([]byte(strings.Join(append([]string{spec.Binary}, spec.Args...), "\x00") + "\x00")), ConfigHash: routeidentity.Hash(data)}
	if err := os.MkdirAll(spec.Dir, 0700); err != nil {
		return err
	}
	encoded, _ := json.Marshal(receipt)
	if err := os.WriteFile(spec.PIDPath, []byte(fmt.Sprintf("%d\n", receipt.PID)), 0600); err != nil {
		return err
	}
	if spec.RouteProof {
		if err := os.WriteFile(spec.PIDPath+routeidentity.ReceiptSuffix, encoded, 0600); err != nil {
			return err
		}
	}
	p.live[spec.ID] = receipt
	return nil
}

func (p *retainedSingModelProcesses) Stop(ctx context.Context, spec ProcessSpec) error {
	_ = os.Remove(spec.PIDPath)
	_ = os.Remove(spec.PIDPath + routeidentity.ReceiptSuffix)
	delete(p.live, spec.ID)
	return p.proxyFakeProcesses.Stop(ctx, spec)
}

func (p *retainedSingModelProcesses) verify(spec ProcessSpec) error {
	if !p.Running(spec) {
		return ErrRetainedSingReview
	}
	data, err := os.ReadFile(spec.MatchArg)
	if err != nil || routeidentity.Hash(data) != p.live[spec.ID].ConfigHash {
		return ErrRetainedSingReview
	}
	var receipt routeidentity.Receipt
	data, err = os.ReadFile(spec.PIDPath + routeidentity.ReceiptSuffix)
	if spec.RouteProof && (err != nil || json.Unmarshal(data, &receipt) != nil || receipt != p.live[spec.ID] || receipt.BootID != p.boot) {
		return ErrRetainedSingReview
	}
	return nil
}

type retainedSingFixture struct {
	m         *Manager
	a         *ProxyTunnelAdapter
	processes *retainedSingModelProcesses
	runner    *proxyFakeRunner
	plan      Plan
	profile   string
	proof     retainedSingProof
	probes    int
	calls     []string
}

type retainedSingModelRunner struct{ fixture *retainedSingFixture }

func (r *retainedSingModelRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	f := r.fixture
	f.calls = append(f.calls, name+" "+strings.Join(args, " "))
	if filepath.Base(name) == "sing-box" {
		name = "sing-box"
	}
	return f.runner.Run(ctx, name, args...)
}

func newRetainedSingFixture(t *testing.T) *retainedSingFixture {
	t.Helper()
	root := t.TempDir()
	configs := engineconfig.New(filepath.Join(root, "stage"), filepath.Join(root, "backups"))
	configs.LiveRoot = filepath.Join(root, "live")
	content, err := configs.ReadExpert("sing-box", "main")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(content.Path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(content.Path, []byte(`{"outbounds":[{"type":"vless","server":"203.0.113.9","server_port":443}]}`), 0600); err != nil {
		t.Fatal(err)
	}
	m := New(filepath.Join(root, "dataplane"))
	a, err := NewProxyTunnelAdapter("sing-box", configs, m.StateRoot)
	if err != nil {
		t.Fatal(err)
	}
	f := &retainedSingFixture{m: m, a: a, profile: "wan-123456789abc"}
	p := &retainedSingModelProcesses{proxyFakeProcesses: &proxyFakeProcesses{running: map[string]bool{}}, boot: "11111111-1111-4111-8111-111111111111", live: map[string]routeidentity.Receipt{}}
	f.processes = p
	f.runner = &proxyFakeRunner{processes: p.proxyFakeProcesses, iface: a.Interface}
	f.a.Processes = p
	f.a.Runner = &retainedSingModelRunner{f}
	f.a.EngineBin = filepath.Join(root, "sing-box")
	f.a.SidecarBin = f.a.EngineBin
	if err := os.WriteFile(f.a.EngineBin, []byte("data-only modeled executable"), 0600); err != nil {
		t.Fatal(err)
	}
	a.IP, a.IPTables, a.IP6Tables = "ip", "iptables", "ip6tables"
	a.Resolver = func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("203.0.113.9")}, nil
	}
	a.bootIdentity = func() (string, error) { return p.boot, nil }
	a.FreshProfile = func(context.Context) (string, error) { return f.profile, nil }
	m.FreshProfile = a.FreshProfile
	a.SOCKSProbe = func(context.Context, string) error { return nil }
	a.Probe = func(context.Context, string) error { f.probes++; return nil }
	a.CanaryProbe = func(context.Context, string, string) error { f.probes++; return nil }
	if err := m.Register(a); err != nil {
		t.Fatal(err)
	}
	f.plan = Plan{SchemaVersion: SchemaVersion, PlanID: "dp-1111111111111111", Digest: strings.Repeat("a", 64), Revision: 1, NetworkProfileID: f.profile, Ready: true, Adapters: []string{"sing-box"},
		Routes: []Route{{ServiceID: "telegram", Selected: "sing-box", Resolved: "sing-box", CIDRs: []string{"198.51.100.20/32"}, Sources: []string{"192.168.1.25/32"}, ProbeURL: "https://telegram.example/"}}}
	f.proof = retainedSingProof{process: func(spec ProcessSpec) (retainedSingProcess, error) {
		if err := p.verify(spec); err != nil {
			return retainedSingProcess{}, err
		}
		info, err := os.Stat(spec.Binary)
		return retainedSingProcess{p.live[spec.ID], info}, err
	}, namespace: func(ProcessSpec) (string, error) { return "modeled-netns-original", nil }}
	return f
}

func (f *retainedSingFixture) apply(t *testing.T) *RetainedSingReview {
	t.Helper()
	execution, availability, err := f.m.applyWithRetainedSingReview(context.Background(), f.plan, nil, f.proof)
	if err != nil || execution.State != "committed" || availability.Code != "available" || availability.Review == nil {
		t.Fatal("original full Manager/Proxy commit did not issue a reader", execution.State, availability.Code, availability.Stage, err)
	}
	t.Cleanup(func() { _ = availability.Review.Close() })
	f.plan, _, err = f.m.Committed()
	if err != nil {
		t.Fatal(err)
	}
	return availability.Review
}

func TestRetainedSingReviewCurrentDoesNotProbeOrMutate(t *testing.T) {
	f := newRetainedSingFixture(t)
	r := f.apply(t)
	if _, err := os.Stat(f.a.sidecarProcess().PIDPath + routeidentity.ReceiptSuffix); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("legacy sidecar launch receipt invented", err)
	}
	f.calls, f.runner.firewall.calls = nil, nil
	starts, probes := len(f.processes.startSpecs), f.probes
	f.a.Probe = func(context.Context, string) error {
		t.Fatal("retained presence re-probed expired service health")
		return errors.New("expired")
	}
	f.a.CanaryProbe = func(context.Context, string, string) error {
		t.Fatal("retained presence ran a canary")
		return errors.New("expired")
	}
	for i := 0; i < 2; i++ {
		if err := r.Current(context.Background(), f.plan); err != nil {
			t.Fatal("unchanged original runtime lost its read-only proof", err)
		}
	}
	if len(f.processes.startSpecs) != starts || f.probes != probes {
		t.Fatal("read-only observation restarted or re-probed a service")
	}
	for _, call := range f.calls {
		if strings.HasPrefix(call, "ip ") && (strings.Contains(call, " add ") || strings.Contains(call, " del ") || strings.Contains(call, " replace ")) || !strings.HasPrefix(call, "ip ") && !strings.HasSuffix(call, " -S") {
			t.Fatal("read-only observation invoked an effect", call)
		}
	}
	committed, _, _ := f.m.Committed()
	if !reflect.DeepEqual(committed, f.plan) {
		t.Fatal("runtime presence promoted health or changed the complete plan")
	}
}

func TestRetainedSingUsesOriginalObserversAfterCallbackSlotReplacement(t *testing.T) {
	f := newRetainedSingFixture(t)
	r := f.apply(t)
	f.m.FreshProfile = func(context.Context) (string, error) {
		t.Fatal("substituted WAN observer called")
		return f.plan.NetworkProfileID, nil
	}
	f.a.bootIdentity = func() (string, error) { t.Fatal("substituted boot observer called"); return "", nil }
	f.a.LANBridgeMembers = func(context.Context, string) ([]string, error) {
		t.Fatal("substituted bridge observer called")
		return nil, nil
	}
	if err := r.Current(context.Background(), f.plan); err != nil {
		t.Fatal("callback slot replacement rebound original observations", err)
	}
	f.profile = "wan-ffffffffffff"
	if err := r.Current(context.Background(), f.plan); err == nil {
		t.Fatal("substituted observer concealed actual WAN drift")
	}
}

func TestRetainedSingUnavailableIsSeparateFromSuccessfulFullApply(t *testing.T) {
	f := newRetainedSingFixture(t)
	commits := 0
	f.proof.process = func(ProcessSpec) (retainedSingProcess, error) {
		return retainedSingProcess{}, errors.New("unknown original process")
	}
	execution, availability, err := f.m.applyWithRetainedSingReview(context.Background(), f.plan, func() (func() error, error) {
		commits++
		return func() error { t.Fatal("optional review failure rolled back a successful Apply"); return nil }, nil
	}, f.proof)
	if err != nil || execution.State != "committed" || availability.Code != "unavailable" || availability.Review != nil || commits != 1 {
		t.Fatal("review unavailability disguised a committed Apply as retryable", execution.State, availability.Code, commits, err)
	}
	if err := f.m.CheckExecutionRecovery(context.Background()); err != nil {
		t.Fatal("optional reader changed the settled full transaction", err)
	}
}

func TestRetainedSingDTOOrDifferentAdapterCannotMintReader(t *testing.T) {
	f := newRetainedSingFixture(t)
	fresh := New(filepath.Join(t.TempDir(), "different-manager"))
	fresh.FreshProfile = f.m.FreshProfile
	f.m = fresh
	fake := &fakeAdapter{id: "sing-box"}
	if err := f.m.Register(fake); err != nil {
		t.Fatal(err)
	}
	f.proof.process = func(ProcessSpec) (retainedSingProcess, error) {
		t.Fatal("non-original adapter reached process proof")
		return retainedSingProcess{}, nil
	}
	execution, available, err := f.m.applyWithRetainedSingReview(context.Background(), f.plan, nil, f.proof)
	if err != nil || execution.State != "committed" || available.Code != "unavailable" || available.Stage != "adapter" || available.Review != nil {
		t.Fatal("ordinary DTO adapter minted a reader or changed full Apply", execution.State, available, err)
	}
	if !slices.Equal(fake.calls, []string{"snapshot", "stage", "validate", "activate", "health", "commit-adapter"}) {
		t.Fatal("wrapper skipped a full Apply phase", fake.calls)
	}
	if (&RetainedSingReview{}).Current(context.Background(), f.plan) == nil {
		t.Fatal("zero reader acquired authority")
	}
}

func TestRetainedSingNormalFullApplyDoesNotCaptureAndRevokesPrior(t *testing.T) {
	f := newRetainedSingFixture(t)
	r := f.apply(t)
	f.plan.PlanID, f.plan.Digest, f.plan.Revision = "dp-2222222222222222", strings.Repeat("b", 64), 2
	r.proof.process = func(ProcessSpec) (retainedSingProcess, error) {
		t.Fatal("ordinary Apply performed optional observation instead of cheap revocation")
		return retainedSingProcess{}, ErrRetainedSingReview
	}
	execution, err := f.m.Apply(context.Background(), f.plan, nil)
	if err != nil || execution.State != "committed" {
		t.Fatal("legacy complete Apply changed", execution.State, err)
	}
	if !r.closed || r.Current(context.Background(), r.plan) == nil || f.m.retainedSing != nil {
		t.Fatal("old reader survived a subsequent complete Apply")
	}
}

func TestRetainedSingReviewCopiesAndJournalReopenCannotAuthorize(t *testing.T) {
	f := newRetainedSingFixture(t)
	r := f.apply(t)
	var copied RetainedSingReview
	reflect.ValueOf(&copied).Elem().Set(reflect.ValueOf(r).Elem()) // Intentional invalid DTO/copy, including its private self pointer.
	if copied.Current(context.Background(), f.plan) == nil || copied.Close() == nil {
		t.Fatal("copied reader acquired original authority")
	}
	if err := r.Current(context.Background(), f.plan); err != nil {
		t.Fatal("copy close damaged the original owner", err)
	}
	reopened := New(f.m.StateRoot)
	reopened.FreshProfile = f.m.FreshProfile
	_ = reopened.Register(f.a)
	if reopened.retainedSing != nil {
		t.Fatal("saved journals reconstructed a process-local reader")
	}
	if err := r.Close(); err != nil || r.Current(context.Background(), f.plan) == nil {
		t.Fatal("closed reader reopened", err)
	}
}

func TestRetainedSingReviewDriftPoisonsWithoutRepair(t *testing.T) {
	for _, drift := range []string{"wan", "boot", "engine-dead", "sidecar-dead", "engine-birth", "sidecar-birth", "engine-config", "sidecar-config", "oversized-config", "receipt", "policy-binding", "policy-receipt", "missing-policy-lock", "forwarding", "registry", "adapter", "manager-root", "committed-plan", "execution", "namespace", "directory"} {
		t.Run(drift, func(t *testing.T) {
			f := newRetainedSingFixture(t)
			r := f.apply(t)
			var path string
			switch drift {
			case "wan":
				f.profile = "wan-ffffffffffff"
			case "boot":
				f.processes.boot = "22222222-2222-4222-8222-222222222222"
			case "engine-dead":
				delete(f.processes.running, f.a.engineProcess().ID)
			case "sidecar-dead":
				delete(f.processes.running, f.a.sidecarProcess().ID)
			case "engine-birth", "sidecar-birth":
				spec := f.a.engineProcess()
				if drift == "sidecar-birth" {
					spec = f.a.sidecarProcess()
				}
				identity := f.processes.live[spec.ID]
				identity.StartTicks = "99999"
				f.processes.live[spec.ID] = identity
			case "oversized-config":
				if err := os.WriteFile(f.a.engineConfigPath(), make([]byte, (8<<20)+1), 0600); err != nil {
					t.Fatal(err)
				}
			case "engine-config":
				path = f.a.engineConfigPath()
			case "sidecar-config":
				path = f.a.sidecarConfigPath()
			case "receipt":
				path = f.a.engineProcess().PIDPath + routeidentity.ReceiptSuffix
			case "policy-binding":
				path = f.a.policyBindingPath()
			case "policy-receipt":
				path = filepath.Join(r.roots[len(r.roots)-1].path, policyAdditionFile)
			case "missing-policy-lock":
				path = filepath.Join(r.roots[len(r.roots)-1].path, policyAdditionLock)
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
			case "forwarding":
				eraseForwardingTable(f.runner.firewall, "iptables", "filter", r.policy.Forwarding.Chain)
			case "registry":
				_ = f.m.Register(&fakeAdapter{id: "unused"})
			case "adapter":
				f.m.Adapters["sing-box"] = &r.frozen
			case "manager-root":
				f.m.StateRoot = filepath.Join(t.TempDir(), "other")
			case "committed-plan":
				path = filepath.Join(f.m.StateRoot, "latest-committed-plan.json")
			case "execution":
				path = filepath.Join(f.m.StateRoot, "latest-execution.json")
			case "namespace":
				r.proof.namespace = func(ProcessSpec) (string, error) { return "foreign-netns", nil }
			case "directory":
				if err := os.Rename(f.a.runtimeRoot(), f.a.runtimeRoot()+"-old"); err != nil {
					t.Skip("platform cannot rename a held root", err)
				}
				if err := os.Mkdir(f.a.runtimeRoot(), 0700); err != nil {
					t.Fatal(err)
				}
			}
			var before []byte
			if path != "" && drift != "missing-policy-lock" {
				var err error
				before, err = os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, append(bytes.Clone(before), ' '), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if err := r.Current(context.Background(), f.plan); err == nil || !r.closed {
				t.Fatal("drift was accepted or kept a revivable reader", drift, err)
			}
			if drift == "missing-policy-lock" {
				if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("read-only observation initialized a missing policy marker", err)
				}
			}
			if before != nil {
				if err := os.WriteFile(path, before, 0600); err != nil {
					t.Fatal(err)
				}
				if r.Current(context.Background(), f.plan) == nil {
					t.Fatal("restoring bytes revived a poisoned reader")
				}
			}
		})
	}
}

func TestRetainedSingReviewCancellationAndWrongExpectedRefuse(t *testing.T) {
	f := newRetainedSingFixture(t)
	r := f.apply(t)
	wrong := cloneExecutionResourcePlan(f.plan)
	wrong.Routes[0].CIDRs = []string{"198.51.100.99/32"}
	if r.Current(context.Background(), wrong) == nil {
		t.Fatal("forged expected full projection accepted")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
	defer cancel()
	<-ctx.Done()
	if err := r.Current(ctx, f.plan); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("caller deadline was hidden", err)
	}
}

func TestRetainedSingFullCompositeApplyAndFailureKeepLegacySemantics(t *testing.T) {
	for _, failure := range []string{"none", "health", "commit-adapter", "store-cas", "post-cas-publication"} {
		t.Run(failure, func(t *testing.T) {
			f := newRetainedSingFixture(t)
			prior := f.apply(t)
			baseline := f.plan
			nfq := &fakeAdapter{id: "nfqws2"}
			if failure == "health" || failure == "commit-adapter" {
				nfq.failAt = failure
			}
			if err := f.m.Register(nfq); err != nil {
				t.Fatal(err)
			}
			f.plan.PlanID, f.plan.Digest, f.plan.Revision = "dp-2222222222222222", strings.Repeat("b", 64), 2
			f.plan.Adapters = []string{"nfqws2", "sing-box"}
			f.plan.Routes = append(f.plan.Routes, Route{ServiceID: "video", Selected: "nfqws2", Resolved: "nfqws2", CIDRs: []string{"198.51.100.40/32"}})
			// Exact private config image + undo callback, as the existing full
			// Manager contract uses. This is not an App/catalog/Store grant.
			configPath := filepath.Join(t.TempDir(), "config.json")
			before, after := []byte(`{"revision":1}`), []byte(`{"revision":2}`)
			if err := os.WriteFile(configPath, before, 0600); err != nil {
				t.Fatal(err)
			}
			commits, undos := 0, 0
			execution, availability, err := f.m.applyWithRetainedSingReview(context.Background(), f.plan, func() (func() error, error) {
				commits++
				if failure == "store-cas" {
					return nil, errors.New("exact config image changed")
				}
				if err := os.WriteFile(configPath, after, 0600); err != nil {
					return nil, err
				}
				blocked := filepath.Join(f.m.StateRoot, "latest-plan.json")
				if failure == "post-cas-publication" {
					blockJournalFile(t, blocked)
				}
				return func() error {
					undos++
					if failure == "post-cas-publication" {
						if err := os.Remove(filepath.Join(blocked, "unrelated")); err != nil {
							return err
						}
						if err := os.Remove(blocked); err != nil {
							return err
						}
					}
					return os.WriteFile(configPath, before, 0600)
				}, nil
			}, f.proof)
			if !prior.closed {
				t.Fatal("new full transaction kept its old reader")
			}
			bytesNow, readErr := os.ReadFile(configPath)
			if readErr != nil {
				t.Fatal(readErr)
			}
			if failure == "none" {
				if err != nil || execution.State != "committed" || availability.Code != "available" || commits != 1 || undos != 0 || !bytes.Equal(bytesNow, after) {
					t.Fatal("full composite Apply changed", execution.State, availability, commits, undos, err)
				}
				t.Cleanup(func() { _ = availability.Review.Close() })
				if !slices.Equal(nfq.calls, []string{"snapshot", "stage", "validate", "activate", "health", "commit-adapter"}) {
					t.Fatal("NFQ participant skipped", nfq.calls)
				}
				if err := availability.Review.Current(context.Background(), availability.Review.plan); err != nil {
					t.Fatal(err)
				}
				return
			}
			if err == nil || execution.State != "rolled-back" || availability.Review != nil || availability.Code != "unavailable" || !nfq.rollback || !bytes.Equal(bytesNow, before) {
				t.Fatal("legacy rollback changed", execution.State, availability, nfq.calls, commits, undos, err)
			}
			wantCommits, wantUndos := 0, 0
			if failure == "store-cas" {
				wantCommits = 1
			}
			if failure == "post-cas-publication" {
				wantCommits, wantUndos = 1, 1
			}
			if commits != wantCommits || undos != wantUndos {
				t.Fatal("config commit/undo changed", commits, undos)
			}
			committed, found, readErr := f.m.Committed()
			if readErr != nil || !found || !reflect.DeepEqual(committed, baseline) {
				t.Fatal("rollback lost the full prior plan", readErr)
			}
			if err := f.m.CheckExecutionRecovery(context.Background()); err != nil {
				t.Fatal("rollback did not settle", err)
			}
		})
	}
}

func TestRetainedSingUnsupportedRequestRefusesBeforeFullApply(t *testing.T) {
	for _, change := range []string{"lan", "dns", "draft", "retire", "safe", "wg", "missing-sing", "generation", "unknown-network"} {
		t.Run(change, func(t *testing.T) {
			f := newRetainedSingFixture(t)
			switch change {
			case "lan":
				f.plan.LAN = &LANPolicyRuntimePlan{}
			case "dns":
				f.plan.SuspendDNS = true
			case "draft":
				f.plan.EngineDrafts = []string{"forged"}
			case "retire":
				f.plan.RetiringAdapters = []string{"nfqws2"}
			case "safe":
				f.plan.SafeMode = true
			case "wg":
				f.plan.Adapters = append(f.plan.Adapters, "wireguard")
			case "missing-sing":
				f.plan.Adapters = []string{"nfqws2"}
			case "generation":
				f.plan.Routes[0].NetworkPolicyGeneration = strings.Repeat("c", 64)
			case "unknown-network":
				f.plan.NetworkProfileID = "network-unknown"
			}
			_, available, err := f.m.applyWithRetainedSingReview(context.Background(), f.plan, func() (func() error, error) { t.Fatal("unsupported request reached config commit"); return nil, nil }, f.proof)
			if !errors.Is(err, ErrRetainedSingReview) || available.Review != nil || len(f.calls) != 0 || len(f.processes.startSpecs) != 0 {
				t.Fatal("unsupported opt-in reached effects", err)
			}
			if _, err := os.Stat(f.m.StateRoot); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("unsupported request wrote a journal", err)
			}
		})
	}
}

func TestRetainedSingMutationEntrypointsRevokeWithoutCapture(t *testing.T) {
	for _, operation := range []string{"record", "deactivate", "recover", "refresh"} {
		t.Run(operation, func(t *testing.T) {
			f := newRetainedSingFixture(t)
			r := f.apply(t)
			switch operation {
			case "record":
				_ = f.m.Record(f.plan)
			case "deactivate":
				_, _ = f.m.Deactivate(context.Background())
			case "recover":
				_, _ = f.m.Recover(context.Background())
			case "refresh":
				_, _ = f.m.RefreshCommitted(context.Background())
			}
			if !r.closed || f.m.retainedSing != nil || r.Current(context.Background(), r.plan) == nil {
				t.Fatal("lifecycle preserved stale reader", operation)
			}
		})
	}
}

func TestRetainedSingFullApplyActualConfigStoreCommitAndExactUndo(t *testing.T) {
	for _, cut := range []string{"committed", "publication-failed"} {
		t.Run(cut, func(t *testing.T) {
			f := newRetainedSingFixture(t)
			_ = f.apply(t)
			store, err := config.Load(filepath.Join(t.TempDir(), "config.json"))
			if err != nil {
				t.Fatal(err)
			}
			if err := store.SetSafeMode(false); err != nil {
				t.Fatal(err)
			}
			if err := store.UpdateService("telegram", config.ServiceState{Enabled: true, Route: "sing-box", Sources: []string{"192.168.1.25/32"}}); err != nil {
				t.Fatal(err)
			}
			if err := store.ApplyDraft(); err != nil {
				t.Fatal(err)
			}
			before := store.Get()
			if err := f.m.Register(&fakeAdapter{id: "nfqws2"}); err != nil {
				t.Fatal(err)
			}
			f.plan.PlanID, f.plan.Digest, f.plan.Revision = "dp-2222222222222222", strings.Repeat("b", 64), before.Revision+1
			f.plan.Adapters = []string{"nfqws2", "sing-box"}
			f.plan.Routes = append(f.plan.Routes, Route{ServiceID: "video", Selected: "nfqws2", Resolved: "nfqws2", CIDRs: []string{"198.51.100.40/32"}})
			blocked := filepath.Join(f.m.StateRoot, "latest-plan.json")
			execution, available, err := f.m.applyWithRetainedSingReview(context.Background(), f.plan, func() (func() error, error) {
				undo, err := store.ApplyAutonomyRouteWithRollback("video", "nfqws2", nil, before.Revision)
				if err != nil {
					return nil, err
				}
				if cut == "publication-failed" {
					blockJournalFile(t, blocked)
				}
				return func() error {
					if cut == "publication-failed" {
						if err := os.Remove(filepath.Join(blocked, "unrelated")); err != nil {
							return err
						}
						if err := os.Remove(blocked); err != nil {
							return err
						}
					}
					return undo()
				}, nil
			}, f.proof)
			if cut == "publication-failed" {
				if err == nil || execution.State != "rolled-back" || available.Review != nil || !reflect.DeepEqual(store.Get(), before) {
					t.Fatal("actual Store undo/full rollback changed", execution.State, err)
				}
				return
			}
			if err != nil || execution.State != "committed" || available.Review == nil {
				t.Fatal("actual Store commit failed", execution.State, err)
			}
			t.Cleanup(func() { _ = available.Review.Close() })
			after := store.Get()
			if !reflect.DeepEqual(before.AppliedServices["telegram"], after.AppliedServices["telegram"]) || !after.AppliedServices["video"].Enabled || after.AppliedServices["video"].Route != "nfqws2" {
				t.Fatal("actual Store touched retained service or lost target")
			}
			if err := available.Review.Current(context.Background(), available.Review.plan); err != nil {
				t.Fatal(err)
			}
		})
	}
}
