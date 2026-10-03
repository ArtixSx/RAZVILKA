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
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/operationgate"
	"github.com/ArtixSx/razvilka/internal/restorejournal"
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
	a := &App{Store: store, Dataplane: dataplane.New(filepath.Join(root, "dataplane")), DataplaneHost: func() dataplane.HostState { return dataplane.HostState{IPCommand: true} }}
	adapter := &defaultRouteTransactionAdapter{id: "wireguard", app: a, verified: true}
	if err := a.Dataplane.Register(adapter); err != nil {
		t.Fatal(err)
	}
	executor, err := NewDefaultRouteExecutor(a, DefaultRouteDependencies{
		Observe: func(context.Context) (DefaultRouteSnapshot, error) { return snapshot, nil },
		BindIngress: func(_ context.Context, _ *DefaultRouteCompilation, input dataplane.Input) (dataplane.Input, error) {
			return input, nil
		},
		Commit: func(expected config.Config, p *config.NetworkPolicy, services map[string]config.ServiceState) (func() error, error) {
			return defaultRouteTestCommit(store, expected, p, services)
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return executor, &snapshot, adapter
}

// An interim test binding for the forthcoming CORE API. It uses the actual
// Store's locked disk+memory CAS and guarded undo rather than a fake Get/PASS.
func defaultRouteTestCommit(store *config.Store, expected config.Config, p *config.NetworkPolicy, services map[string]config.ServiceState) (func() error, error) {
	ctx := context.Background()
	cfg := store.Get()
	if !reflect.DeepEqual(cfg, expected) {
		return nil, config.ErrRevisionChanged
	}
	session, err := store.BeginRestore(ctx)
	if err != nil {
		return nil, err
	}
	before, err := session.Read(ctx)
	if err != nil {
		_ = session.Close()
		return nil, err
	}
	current, _, err := config.InspectBytes(before.Data)
	if err != nil || !reflect.DeepEqual(current, cfg) {
		_ = session.Close()
		return nil, config.ErrRevisionChanged
	}
	current.AppliedNetworkPolicy, current.AppliedServices = config.CloneNetworkPolicy(p), defaultRouteCloneServices(services)
	current.Revision++
	current.AppliedRevision = current.Revision
	current.LastAppliedAt = time.Now().UTC().Format(time.RFC3339)
	data, _ := json.Marshal(current)
	after := restorejournal.Image{Exists: true, Data: data}
	err = errors.Join(session.CompareAndSwap(ctx, before, after), session.Close())
	if err != nil {
		return nil, err
	}
	return func() error {
		session, err := store.BeginRestore(ctx)
		if err != nil {
			return err
		}
		return errors.Join(session.CompareAndSwap(ctx, after, before), session.Close())
	}, nil
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
			switch mode {
			case "stop":
				adapter.afterActivate = func() { s.Stopped = true; s.Authority.Sequence++ }
			case "cancel":
				adapter.afterActivate = cancel
			case "cas":
				e.deps.Commit = func(config.Config, *config.NetworkPolicy, map[string]config.ServiceState) (func() error, error) {
					return nil, config.ErrRevisionChanged
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
	if name == "ip" && strings.Join(args, " ") == "-j route get 93.184.216.34 mark 0" {
		return []byte(`[{"dst":"93.184.216.34","dev":"eth0","prefsrc":"192.0.2.2","gateway":"192.0.2.1","table":254}]`), nil
	}
	return nil, errors.New("no live interface in test")
}

func TestDefaultRouteActualWireGuardAdapterCurrentlyRefusesEndpointOverlap(t *testing.T) {
	defaultRouteRequireLinuxJournal(t)
	e, _, _ := defaultRouteExecutorFixture(t)
	// Replace the transaction double with the actual registered WG adapter;
	// native kernel calls remain refused. This is actual Stage behavior, not
	// packet/native PASS and not an excuse to carve endpoint out of LAN scope.
	root := t.TempDir()
	profiles := wireguardprofile.New(filepath.Join(root, "profiles"))
	profile := "[Interface]\nPrivateKey = " + base64.StdEncoding.EncodeToString([]byte(strings.Repeat("a", 32))) + "\nAddress = 10.66.0.2/32\n[Peer]\nPublicKey = " + base64.StdEncoding.EncodeToString([]byte(strings.Repeat("b", 32))) + "\nEndpoint = 93.184.216.34:51820\nAllowedIPs = 0.0.0.0/0, ::/0\n"
	if _, err := profiles.Put(context.Background(), "reserve", "Own server", profile, ""); err != nil {
		t.Fatal(err)
	}
	adapter := dataplane.NewWireGuardAdapter(nil, e.app.Dataplane.StateRoot)
	adapter.Profiles = profiles
	runner := &defaultRouteReadOnlyRunner{}
	adapter.Runner, adapter.WG, adapter.IP = runner, "wg", "ip"
	e.app.Dataplane = dataplane.New(filepath.Join(root, "manager"))
	if err := e.app.Dataplane.Register(adapter); err != nil {
		t.Fatal(err)
	}
	r, err := e.Review(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = e.Execute(context.Background(), r, r.Digest())
	if err == nil || !strings.Contains(err.Error(), "overlaps selected service prefix") {
		t.Fatal("unimplemented WG default falsely accepted", err)
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
