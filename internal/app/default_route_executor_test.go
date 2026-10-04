package app

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/operationgate"
	"github.com/ArtixSx/razvilka/internal/wireguardprofile"
)

// These transaction doubles test admission/ordering/fences, never packet
// success. The separate actual-WG test below consumes the production adapter.
type defaultRouteTransactionAdapter struct {
	id                     string
	app                    *App
	steps                  []string
	afterActivate          func()
	healthErr, rollbackErr error
	verified               bool
	live                   bool
}

func (a *defaultRouteTransactionAdapter) ID() string { return a.id }
func (a *defaultRouteTransactionAdapter) step(ctx context.Context, phase string) error {
	if _, err := a.app.Operations.Enter(context.Background()); !errors.Is(err, operationgate.ErrBusy) {
		return errors.New("adapter entered without exclusive admission")
	}
	a.steps = append(a.steps, phase)
	return ctx.Err()
}
func (a *defaultRouteTransactionAdapter) Snapshot(c context.Context, _ dataplane.Plan, _ string) error {
	return a.step(c, "snapshot")
}
func (a *defaultRouteTransactionAdapter) Stage(c context.Context, _ dataplane.Plan, _ string) error {
	return a.step(c, "stage")
}
func (a *defaultRouteTransactionAdapter) Validate(c context.Context, _ dataplane.Plan, _ string) error {
	return a.step(c, "validate")
}
func (a *defaultRouteTransactionAdapter) Activate(c context.Context, _ dataplane.Plan, _ string) error {
	a.live = true
	if a.afterActivate != nil {
		a.afterActivate()
	}
	return a.step(c, "activate")
}
func (a *defaultRouteTransactionAdapter) Health(c context.Context, _ dataplane.Plan, _ string) error {
	return errors.Join(a.step(c, "health"), a.healthErr)
}
func (a *defaultRouteTransactionAdapter) Commit(c context.Context, _ dataplane.Plan, _ string) error {
	return a.step(c, "commit")
}
func (a *defaultRouteTransactionAdapter) Rollback(c context.Context, _ dataplane.Plan, _ string) error {
	if c.Err() != nil {
		return errors.New("rollback inherited cancellation")
	}
	a.live = false
	return errors.Join(a.step(c, "rollback"), a.rollbackErr)
}
func (a *defaultRouteTransactionAdapter) VerifyRollback(c context.Context, _ dataplane.Plan, _ string) (bool, error) {
	return a.verified && !a.live, a.step(c, "verify-rollback")
}

func defaultRouteExecutorFixture(t *testing.T) (*DefaultRouteExecutor, *DefaultRouteSnapshot, *defaultRouteTransactionAdapter) {
	t.Helper()
	cfg, snapshot, _ := defaultRouteFixture()
	return defaultRouteExecutorFixtureConfig(t, cfg, snapshot)
}

func defaultRouteExecutorFixtureConfig(t *testing.T, cfg config.Config, snapshot DefaultRouteSnapshot) (*DefaultRouteExecutor, *DefaultRouteSnapshot, *defaultRouteTransactionAdapter) {
	t.Helper()
	root := t.TempDir()
	path := filepath.Join(root, "config.json")
	bytes, _ := json.Marshal(cfg)
	if err := os.WriteFile(path, bytes, 0o600); err != nil {
		t.Fatal(err)
	}
	store, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	a := &App{Store: store, Dataplane: dataplane.New(filepath.Join(root, "dataplane")), DataplaneHost: func() dataplane.HostState {
		return dataplane.HostState{IPCommand: true, IPTables: true, IP6Tables: true}
	}}
	a.Dataplane.FreshProfile = func(context.Context) (string, error) { return snapshot.Scope.NetworkID, nil }
	adapter := &defaultRouteTransactionAdapter{id: "wireguard", app: a, verified: true}
	if err := a.Dataplane.Register(adapter); err != nil {
		t.Fatal(err)
	}
	// Explicit protocol double for the LAN participant; concrete mixed-receipt
	// execution is covered by dataplane tests and independent native replay.
	if err := a.Dataplane.Register(&defaultRouteTransactionAdapter{id: dataplane.NetworkPolicyAdapterID, app: a, verified: true}); err != nil {
		t.Fatal(err)
	}
	executor, err := NewDefaultRouteExecutor(a, DefaultRouteDependencies{
		Observe: func(context.Context) (DefaultRouteSnapshot, error) { return snapshot, nil },
		BindIngress: func(_ context.Context, _ *DefaultRouteCompilation, input dataplane.Input) (dataplane.Input, error) {
			return input, nil
		},
		Commit: store.CommitNetworkPolicyWithRollback,
	})
	if err != nil {
		t.Fatal(err)
	}
	return executor, &snapshot, adapter
}

func TestDefaultRouteExecutorSingleManagerCommitAndReviewCopies(t *testing.T) {
	defaultRouteRequireLinuxJournal(t)
	e, _, adapter := defaultRouteExecutorFixture(t)
	r, err := e.Review(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	view := r.Plan()
	view.Routes[0].CIDRs[0] = "0.0.0.0/0"
	view.Adapters[0] = "nfqws2"
	execution, err := e.Execute(context.Background(), r, r.Digest())
	if err != nil || execution.State != "committed" {
		t.Fatalf("execution %+v err %v", execution, err)
	}
	if strings.Join(adapter.steps, ",") != "snapshot,stage,validate,activate,health,commit" {
		t.Fatal("unexpected phases", adapter.steps)
	}
	current := e.app.Store.Get()
	if current.AppliedNetworkPolicy == nil || current.AppliedRevision != 9 || current.Revision != 9 || len(current.AppliedServices) != 0 || !adapter.live {
		t.Fatal("policy/default without services not committed")
	}
	committed, exists, err := e.app.Dataplane.Committed()
	if err != nil || !exists || committed.Revision != current.AppliedRevision {
		t.Fatal("config/dataplane revisions differ", err)
	}
	if _, err := e.Execute(context.Background(), r, r.Digest()); !errors.Is(err, dataplane.ErrReviewChanged) {
		t.Fatal("review replay accepted", err)
	}
	if _, err := e.Review(context.Background(), nil); err != nil {
		t.Fatal("next review could not consume applied state", err)
	}
}

func TestDefaultRouteExecutorRealCommitServiceFencesAndEpochRollback(t *testing.T) {
	defaultRouteRequireLinuxJournal(t)
	for _, changedEpoch := range []bool{false, true} {
		t.Run(map[bool]string{false: "commit", true: "post-commit-epoch-rollback"}[changedEpoch], func(t *testing.T) {
			cfg, snapshot, _ := defaultRouteFixture()
			node := "node-" + strings.Repeat("a", 64)
			cfg.Services["changed"] = config.ServiceState{Route: "xray:" + node, Mode: "xray:" + node, Sources: []string{"192.168.1.40/32"}}
			cfg.Services["stable"] = config.ServiceState{Route: "direct", Mode: "direct"}
			cfg.AppliedServices = map[string]config.ServiceState{
				"changed": {Enabled: true, Route: "warp-wg", Mode: "warp-wg", Sources: []string{"192.168.1.50/32"}},
				"removed": {Enabled: true, Route: "wireguard", Mode: "wireguard"},
				"stable":  cfg.Services["stable"],
			}
			cfg.ServicePolicies = map[string]config.ServicePolicy{}
			for _, id := range []string{"changed", "removed", "stable"} {
				p := config.DefaultServicePolicy(id, cfg.AppliedServices[id])
				p.Enabled, p.Mode, p.LegacyOptIn, p.Revision = true, "auto", true, 3
				p.AllowedNodeIDs = []string{node}
				cfg.ServicePolicies[id] = p
			}
			e, s, adapter := defaultRouteExecutorFixtureConfig(t, cfg, snapshot)
			if err := e.app.Store.Save(); err != nil {
				t.Fatal(err)
			}
			before := e.app.Store.Get()
			path := filepath.Join(filepath.Dir(e.app.Dataplane.StateRoot), "config.json")
			beforeBytes, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if changedEpoch {
				commit := e.deps.Commit
				e.deps.Commit = func(expected config.Config, p *config.NetworkPolicy, services map[string]config.ServiceState) (func() error, error) {
					undo, err := commit(expected, p, services)
					if err == nil {
						s.Authority.Sequence++ // Durable config commit cannot bypass a newer control owner.
					}
					return undo, err
				}
			}
			r, err := e.Review(context.Background(), nil)
			if err != nil {
				t.Fatal(err)
			}
			execution, err := e.Execute(context.Background(), r, r.Digest())
			after := e.app.Store.Get()
			if changedEpoch {
				if err == nil || execution.State != "rolled-back" || !execution.RollbackVerified || adapter.live || !reflect.DeepEqual(before, after) {
					t.Fatal("epoch change did not restore applied policy and service fences", err, execution)
				}
				afterBytes, readErr := os.ReadFile(path)
				if readErr != nil || string(afterBytes) != string(beforeBytes) {
					t.Fatal("guarded undo failed to restore canonical preimage", readErr)
				}
				return
			}
			if err != nil || execution.State != "committed" || !adapter.live {
				t.Fatal("real commit rejected sanctioned service fences", err, execution)
			}
			changed, removed := after.ServicePolicies["changed"], after.ServicePolicies["removed"]
			if changed.Enabled || changed.Mode != "manual" || changed.LegacyOptIn || changed.Revision != 4 || changed.PinnedNodeID != node || !reflect.DeepEqual(changed.DeviceSources, cfg.Services["changed"].Sources) ||
				removed.Enabled || removed.Mode != "manual" || removed.LegacyOptIn || removed.Revision != 4 || removed.PinnedNodeID != "" || len(removed.DeviceSources) != 0 {
				t.Fatal("changed/removed automatic authority was not fenced", changed, removed)
			}
			if !reflect.DeepEqual(after.ServicePolicies["stable"], before.ServicePolicies["stable"]) || !reflect.DeepEqual(after.Services, before.Services) || !reflect.DeepEqual(after.NetworkPolicy, before.NetworkPolicy) {
				t.Fatal("commit changed unaffected policy or editor")
			}
		})
	}
}

func TestDefaultRouteExecutorRealCommitPreservesEmptyPolicyMapPreimage(t *testing.T) {
	defaultRouteRequireLinuxJournal(t)
	e, _, adapter := defaultRouteExecutorFixture(t)
	p := config.DefaultServicePolicy("temporary", config.ServiceState{})
	if _, err := e.app.Store.UpdateServicePolicy(p, e.app.Store.Get().Revision, 0); err != nil {
		t.Fatal(err)
	}
	if err := e.app.Store.DeleteService("temporary"); err != nil {
		t.Fatal(err)
	}
	if c := e.app.Store.Get(); c.ServicePolicies == nil || len(c.ServicePolicies) != 0 {
		t.Fatal("fixture did not retain empty policy map")
	}
	r, err := e.Review(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	execution, err := e.Execute(context.Background(), r, r.Digest())
	if err != nil || execution.State != "committed" || !adapter.live || e.app.Store.Get().ServicePolicies == nil {
		t.Fatal("JSON representation weakened the exact Store preimage", err, execution)
	}
}

func TestDefaultRouteCommittedPostimageRejectsExtraChangesAndUnboundTime(t *testing.T) {
	cfg, _, now := defaultRouteFixture()
	services := map[string]config.ServiceState{"disabled": {Route: "direct"}}
	after, err := config.ReviewedNetworkPolicyCommitImage(cfg, cfg.NetworkPolicy, services, now)
	if err != nil {
		t.Fatal(err)
	}
	started, finished := now.Add(-time.Millisecond), now.Add(time.Millisecond)
	if !defaultRouteCommittedConfig(cfg, after, cfg.NetworkPolicy, services, started, finished) {
		t.Fatal("canonical normalized shared postimage rejected")
	}
	for name, mutate := range map[string]func(*config.Config){
		"editor": func(c *config.Config) { c.Services["new"] = config.ServiceState{Route: "direct"} },
		"policy": func(c *config.Config) { c.NetworkPolicy.Clients.NewDevices = "base" },
		"safe":   func(c *config.Config) { c.SafeMode = true },
		"listen": func(c *config.Config) { c.Listen = ":12345" },
		"applied state": func(c *config.Config) {
			c.AppliedServices["disabled"] = config.ServiceState{Enabled: true, Route: "direct", Mode: "direct"}
		},
		"old timestamp":    func(c *config.Config) { c.LastAppliedAt = now.Add(-time.Hour).UTC().Format(time.RFC3339) },
		"future timestamp": func(c *config.Config) { c.LastAppliedAt = now.Add(time.Hour).UTC().Format(time.RFC3339) },
		"noncanonical UTC": func(c *config.Config) { c.LastAppliedAt = strings.TrimSuffix(c.LastAppliedAt, "Z") + "+00:00" },
		"missing time":     func(c *config.Config) { c.LastAppliedAt = "" },
	} {
		t.Run(name, func(t *testing.T) {
			changed := defaultRouteCloneConfig(after)
			mutate(&changed)
			if defaultRouteCommittedConfig(cfg, changed, cfg.NetworkPolicy, services, started, finished) {
				t.Fatal("unreviewed committed delta accepted")
			}
		})
	}
	if defaultRouteCommittedConfig(cfg, after, cfg.NetworkPolicy, services, time.Time{}, finished) ||
		defaultRouteCommittedConfig(cfg, after, cfg.NetworkPolicy, services, finished, started) {
		t.Fatal("missing or inverted commit time interval accepted")
	}
}

func TestDefaultRouteExecutorChangedReviewNeverStarts(t *testing.T) {
	for name, change := range map[string]func(*DefaultRouteExecutor, *DefaultRouteSnapshot){
		"network":          func(_ *DefaultRouteExecutor, s *DefaultRouteSnapshot) { s.Scope.NetworkID = "wan-222222222222" },
		"control sequence": func(_ *DefaultRouteExecutor, s *DefaultRouteSnapshot) { s.Authority.Sequence++ },
		"scope":            func(_ *DefaultRouteExecutor, s *DefaultRouteSnapshot) { s.Scope.Revision++ },
		"consent": func(_ *DefaultRouteExecutor, s *DefaultRouteSnapshot) {
			s.Authority.ConsentDigest = strings.Repeat("7", 64)
		},
		"profile generation": func(_ *DefaultRouteExecutor, s *DefaultRouteSnapshot) { s.ProfileGeneration++ },
		"node generation":    func(_ *DefaultRouteExecutor, s *DefaultRouteSnapshot) { s.NodeGeneration++ },
		"stop":               func(_ *DefaultRouteExecutor, s *DefaultRouteSnapshot) { s.Stopped = true },
		"safe mode":          func(e *DefaultRouteExecutor, _ *DefaultRouteSnapshot) { _ = e.app.Store.SetSafeMode(true) },
		"external disk": func(e *DefaultRouteExecutor, _ *DefaultRouteSnapshot) {
			path := filepath.Join(filepath.Dir(e.app.Dataplane.StateRoot), "config.json")
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, append(data, '\n'), 0o600); err != nil {
				t.Fatal(err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			if name == "safe mode" {
				defaultRouteRequireLinuxJournal(t)
			}
			e, s, adapter := defaultRouteExecutorFixture(t)
			r, err := e.Review(context.Background(), nil)
			if err != nil {
				t.Fatal(err)
			}
			change(e, s)
			if _, err := e.Execute(context.Background(), r, r.Digest()); !errors.Is(err, dataplane.ErrReviewChanged) || len(adapter.steps) != 0 {
				t.Fatal("changed review mutated runtime", err, adapter.steps)
			}
		})
	}
}

func TestDefaultRouteExecutorStopCancelCASAndVerifiedRollback(t *testing.T) {
	defaultRouteRequireLinuxJournal(t)
	for _, mode := range []string{"stop", "cancel", "health", "cas", "rollback-failed", "rollback-unverified"} {
		t.Run(mode, func(t *testing.T) {
			e, s, adapter := defaultRouteExecutorFixture(t)
			before := e.app.Store.Get()
			r, err := e.Review(context.Background(), nil)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var foreignBytes []byte
			switch mode {
			case "stop":
				adapter.afterActivate = func() { s.Stopped = true; s.Authority.Sequence++ }
			case "cancel":
				adapter.afterActivate = cancel
			case "cas":
				adapter.afterActivate = func() {
					// Same semantic config, different exact disk preimage. The
					// REAL Store commit must reject it and preserve foreign bytes.
					path := filepath.Join(filepath.Dir(e.app.Dataplane.StateRoot), "config.json")
					data, err := os.ReadFile(path)
					if err != nil {
						t.Fatal(err)
					}
					foreignBytes = append(data, '\n')
					if err := os.WriteFile(path, foreignBytes, 0o600); err != nil {
						t.Fatal(err)
					}
				}
			default:
				adapter.healthErr = errors.New("actual outbound health failed")
			}
			if mode == "rollback-failed" {
				adapter.rollbackErr = errors.New("readback unknown")
			}
			if mode == "rollback-unverified" {
				adapter.verified = false
			}
			execution, err := e.Execute(ctx, r, r.Digest())
			if err == nil || adapter.live || !reflect.DeepEqual(before, e.app.Store.Get()) {
				t.Fatalf("failed path accepted %+v %v", execution, err)
			}
			if mode == "cas" {
				path := filepath.Join(filepath.Dir(e.app.Dataplane.StateRoot), "config.json")
				data, err := os.ReadFile(path)
				if err != nil || string(data) != string(foreignBytes) {
					t.Fatal("rollback overwrote the foreign disk preimage", err)
				}
			}
			wantFence := mode == "rollback-failed" || mode == "rollback-unverified"
			if e.app.Operations.Snapshot().Fenced != wantFence {
				t.Fatal("incorrect recovery fence", execution)
			}
			if !wantFence && (!execution.RollbackVerified || execution.State != "rolled-back") {
				t.Fatal("rollback not independently verified", execution)
			}
			if !strings.Contains(strings.Join(adapter.steps, ","), "rollback,verify-rollback") {
				t.Fatal("rollback not joined", adapter.steps)
			}
		})
	}
}

func TestDefaultRouteExecutorPostCommitDiskReplacementRefusesAndFences(t *testing.T) {
	defaultRouteRequireLinuxJournal(t)
	e, _, adapter := defaultRouteExecutorFixture(t)
	r, err := e.Review(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(filepath.Dir(e.app.Dataplane.StateRoot), "config.json")
	commit := e.deps.Commit
	var foreignBytes []byte
	e.deps.Commit = func(expected config.Config, p *config.NetworkPolicy, services map[string]config.ServiceState) (func() error, error) {
		undo, err := commit(expected, p, services)
		if err != nil {
			return undo, err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return undo, err
		}
		foreignBytes = append(data, '\n')
		return undo, os.WriteFile(path, foreignBytes, 0o600)
	}
	execution, err := e.Execute(context.Background(), r, r.Digest())
	if !errors.Is(err, dataplane.ErrReviewChanged) || execution.State != "rollback-failed" || execution.RollbackVerified || adapter.live || !e.app.Operations.Snapshot().Fenced {
		t.Fatal("post-commit foreign disk image accepted or unknown undo unfenced", err, execution)
	}
	data, readErr := os.ReadFile(path)
	if readErr != nil || string(data) != string(foreignBytes) {
		t.Fatal("guarded undo overwrote the foreign postimage", readErr)
	}
	if _, exists, err := e.app.Dataplane.Committed(); err != nil || exists {
		t.Fatal("new dataplane generation published despite unknown config undo", err)
	}
}

func TestDefaultRouteExecutorDiskChangeDuringObservationNeverStarts(t *testing.T) {
	e, _, adapter := defaultRouteExecutorFixture(t)
	r, err := e.Review(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	observe := e.deps.Observe
	path := filepath.Join(filepath.Dir(e.app.Dataplane.StateRoot), "config.json")
	var foreignBytes []byte
	e.deps.Observe = func(ctx context.Context) (DefaultRouteSnapshot, error) {
		snapshot, err := observe(ctx)
		if err != nil {
			return snapshot, err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return snapshot, err
		}
		foreignBytes = append(data, '\n')
		return snapshot, os.WriteFile(path, foreignBytes, 0o600)
	}
	if _, err := e.Execute(context.Background(), r, r.Digest()); !errors.Is(err, dataplane.ErrReviewChanged) || len(adapter.steps) != 0 {
		t.Fatal("disk replacement during final observation escaped before effects", err, adapter.steps)
	}
	data, readErr := os.ReadFile(path)
	if readErr != nil || string(data) != string(foreignBytes) {
		t.Fatal("preflight overwrote external disk change", readErr)
	}
}

func TestDefaultRouteExecutorCrashJournalRefusesBeforeAdapter(t *testing.T) {
	e, _, adapter := defaultRouteExecutorFixture(t)
	r, err := e.Review(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(e.app.Dataplane.StateRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(e.app.Dataplane.StateRoot, "latest-execution.json"), []byte(`{"plan_id":"dp-crashed","digest":"unknown","state":"applying"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := e.Execute(context.Background(), r, r.Digest()); !errors.Is(err, dataplane.ErrExecutionJournal) || len(adapter.steps) != 0 || !e.app.Operations.Snapshot().Fenced {
		t.Fatal("unfinished journal reused", err)
	}
}

func TestDefaultRouteExecutorMissingAndWeakeningBindingsRefused(t *testing.T) {
	e, _, _ := defaultRouteExecutorFixture(t)
	if _, err := NewDefaultRouteExecutor(e.app, DefaultRouteDependencies{}); !errors.Is(err, ErrDefaultRouteCapability) {
		t.Fatal("missing shared primitive accepted")
	}
	e.deps.BindIngress = func(_ context.Context, _ *DefaultRouteCompilation, p dataplane.Input) (dataplane.Input, error) {
		p.Routes = nil
		return p, nil
	}
	if _, err := e.Review(context.Background(), nil); !errors.Is(err, ErrDefaultRouteCapability) {
		t.Fatal("binder silently dropped default", err)
	}
}

type defaultRouteReadOnlyRunner struct{ calls []string }

func (r *defaultRouteReadOnlyRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	r.calls = append(r.calls, name+" "+strings.Join(args, " "))
	if name == "ip" {
		switch strings.Join(args, " ") {
		case "-j route get 93.184.216.34 mark 0":
			return []byte(`[{"dst":"93.184.216.34","dev":"eth0","prefsrc":"192.0.2.2","gateway":"192.0.2.1","table":254}]`), nil
		case "route show table main default", "-6 route show table main default":
			// The reviewed LAN bridge is currently also a WAN default device.
			return []byte("default dev br0\n"), nil
		case "route show table main":
			return []byte("192.168.1.0/24 dev br0 proto kernel scope link src 192.168.1.1\n"), nil
		case "-6 route show table main":
			return []byte("fd00::/64 dev br0 proto kernel metric 256\n"), nil
		}
	}
	return nil, errors.New("no live interface in test")
}

func TestDefaultRouteActualWireGuardAdapterRefusesUnsafeScopeAndLegacyEndpointOverlap(t *testing.T) {
	defaultRouteRequireLinuxJournal(t)
	e, observed, _ := defaultRouteExecutorFixture(t)
	// Replace the transaction double with the actual registered WG adapter;
	// Read-only physical responses model the reviewed bridge becoming WAN.
	// DEFAULT now has a separate endpoint transport pin, so public endpoint
	// overlap alone is no longer a refusal for this network policy path.
	root := t.TempDir()
	profiles := wireguardprofile.New(filepath.Join(root, "profiles"))
	profile := "[Interface]\nPrivateKey = " + base64.StdEncoding.EncodeToString([]byte(strings.Repeat("a", 32))) + "\nAddress = 10.66.0.2/32\n[Peer]\nPublicKey = " + base64.StdEncoding.EncodeToString([]byte(strings.Repeat("b", 32))) + "\nEndpoint = 93.184.216.34:51820\nAllowedIPs = 0.0.0.0/0, ::/0\n"
	imported, err := profiles.Put(context.Background(), "reserve", "Own server", profile, "")
	if err != nil {
		t.Fatal(err)
	}
	path := observed.Paths["default"]
	path.WireGuardProfileRevision = imported.Revision
	observed.Paths["default"] = path
	adapter := dataplane.NewWireGuardAdapter(nil, e.app.Dataplane.StateRoot)
	adapter.Profiles = profiles
	runner := &defaultRouteReadOnlyRunner{}
	adapter.Runner, adapter.WG, adapter.IP = runner, "wg", "ip"
	e.app.Dataplane = dataplane.New(filepath.Join(root, "manager"))
	e.app.Dataplane.FreshProfile = func(ctx context.Context) (string, error) {
		snapshot, err := e.deps.Observe(ctx)
		return snapshot.Scope.NetworkID, err
	}
	if err := e.app.Dataplane.Register(&defaultRouteTransactionAdapter{id: dataplane.NetworkPolicyAdapterID, app: e.app, verified: true}); err != nil {
		t.Fatal(err)
	}
	if err := e.app.Dataplane.Register(adapter); err != nil {
		t.Fatal(err)
	}
	r, err := e.Review(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = e.Execute(context.Background(), r, r.Digest())
	if err == nil || !strings.Contains(err.Error(), "no directly connected private LAN bridge prefix could be proven") {
		t.Fatal("WAN bridge acquired DEFAULT forwarding authority", err)
	}
	for _, read := range []string{"ip route show table main default", "ip -6 route show table main default"} {
		if !slices.Contains(runner.calls, read) {
			t.Fatal("physical refusal did not inspect exact current routes", read, runner.calls)
		}
	}
	if !slices.Contains(runner.calls, "ip route show table main") && !slices.Contains(runner.calls, "ip -6 route show table main") {
		t.Fatal("WAN bridge refusal omitted connected LAN readback", runner.calls)
	}
	// The legacy service path has no separate network transport table and must
	// still refuse the original endpoint/service-prefix loop before effects.
	legacy := dataplane.Plan{Routes: []dataplane.Route{{ServiceID: "legacy", Resolved: "wireguard:reserve", CIDRs: []string{"93.184.216.0/24"}, WireGuardProfileRevision: imported.Revision}}}
	legacyRoot := t.TempDir()
	legacyCtx := dataplane.WithReviewGuard(context.Background(), func(c context.Context) error { return c.Err() })
	if err := adapter.Snapshot(legacyCtx, legacy, legacyRoot); err != nil {
		t.Fatal(err)
	}
	if err := adapter.Stage(legacyCtx, legacy, legacyRoot); err == nil || !strings.Contains(err.Error(), "overlaps selected service prefix") {
		t.Fatal("legacy endpoint overlap acquired forwarding authority", err)
	}
	for _, call := range runner.calls {
		if strings.Contains(call, "link add") || strings.Contains(call, "rule add") || strings.Contains(call, "setconf") {
			t.Fatal("refused stage mutated kernel", runner.calls)
		}
	}
}

func defaultRouteRequireLinuxJournal(t *testing.T) {
	t.Helper()
	if runtime.GOOS != "linux" && os.Getenv("RAZVILKA_DEFAULT_WINDOWS_JOURNAL_TESTS") != "1" {
		t.Skip("journal/CAS fixture: Windows sandbox refuses ownedfs renameat; explicit local Windows test run or coordinator's Linux checks required")
	}
}
