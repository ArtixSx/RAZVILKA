package dataplane

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// Actual scoped compiler/readback/mixed receipt with an explicit kernel and
// ECHILD/ACK model. These tests do not execute a helper or native process.
type executionNFQWSFixture struct {
	m       *Manager
	p       Plan
	spec    NFQWSScopedSpec
	b       *NFQWSScopedBinding
	model   *nfqwsScopedModel
	r       *NFQWSExecutionResource
	ctx     context.Context
	proofs  []nfqwsExecutionReadbackMode
	onProof func(nfqwsExecutionReadbackMode)
}

func executionNFQWSManagerFixture(t *testing.T) *executionNFQWSFixture {
	t.Helper()
	p, spec, _ := nfqwsScopedFixture(t)
	p.PlanID, p.NetworkProfileID = "dp-0123456789abcdef", "wan-0123456789ab"
	p.Routes[0].NetworkPolicyRole = "override"
	p.Adapters = []string{"nfqws2"}
	b, model, root := nfqwsScopedBindingFixture(t)
	model.running = false
	m := New(root)
	m.FreshProfile = func(context.Context) (string, error) { return p.NetworkProfileID, nil }
	if err := m.Register(&fakeAdapter{id: "nfqws2"}); err != nil {
		t.Fatal(err)
	}
	if err := m.recordLocked(p); err != nil {
		t.Fatal(err)
	}
	return &executionNFQWSFixture{m: m, p: p, spec: spec, b: b, model: model, ctx: WithReviewGuard(context.Background(), func(c context.Context) error { return c.Err() })}
}

func (f *executionNFQWSFixture) latest(t *testing.T) Execution {
	t.Helper()
	var execution *Execution
	if found, err := readOptionalJournal(filepath.Join(f.m.StateRoot, "latest-execution.json"), &execution); err != nil || !found || execution == nil {
		t.Fatal("missing actual journal", err)
	}
	return *execution
}

func (f *executionNFQWSFixture) bind(t *testing.T, ctx context.Context) context.Context {
	t.Helper()
	readback := nfqwsExecutionReadback(func(c context.Context, p *NFQWSScopedPlan, root string, mode nfqwsExecutionReadbackMode) error {
		if f.r == nil || p != f.r.Plan() || root != f.r.Root() {
			return ErrNFQWSScopedOwner
		}
		f.proofs = append(f.proofs, mode)
		if mode == nfqwsExecutionBeforeStart && f.latest(t).Resources[0].Phase != "process-pending" {
			t.Fatal("owner pre-start proof ran before durable process-pending")
		}
		// This private copy is used only for these read-only helpers. The
		// actual writer below keeps the independent capture-ready guard.
		readOnly := *f.b
		readOnly.ApplyGuard = func(c context.Context, _ *NFQWSScopedPlan, _ PolicyEffect) error {
			return f.r.Current(c, f.r.Binding())
		}
		var err error
		switch mode {
		case nfqwsExecutionBeforeStart:
			err = readOnly.CheckBeforeProcessStart(c, p)
		case nfqwsExecutionPrepared:
			err = readOnly.VerifyPrepared(c, p, root)
		case nfqwsExecutionRemoved:
			err = f.b.VerifyInactive(c, p, root)
		default:
			err = ErrNFQWSScopedOwner
		}
		if f.onProof != nil {
			f.onProof(mode)
		}
		return err
	})
	ctx = context.WithValue(ctx, nfqwsExecutionReadbackKey{}, readback)
	r, err := AcquireNFQWSExecutionResource(ctx, f.spec)
	if err != nil {
		t.Fatal(err)
	}
	f.r = r
	*f.model.p = *r.Plan() // Preserve the model callbacks' original pointer.
	f.b.ApplyGuard, f.b.CleanupGuard = r.ApplyGuard, r.CleanupGuard
	return ctx
}

func (f *executionNFQWSFixture) start(t *testing.T, ctx context.Context) {
	t.Helper()
	if err := f.r.BeforeStart(ctx, f.r.Binding()); err != nil {
		t.Fatal(err)
	}
	bounded, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	if err := f.r.WithStart(bounded, f.r.Binding(), func() error {
		if f.latest(t).Resources[0].Phase != "process-pending" {
			t.Fatal("actual Start before durable reservation")
		}
		if f.r.scope.startMu.TryLock() {
			f.r.scope.startMu.Unlock()
			t.Fatal("Start ACK interval did not hold close barrier")
		}
		f.model.running = true
		return nil // Explicit Start ACK model, not process proof.
	}); err != nil {
		t.Fatal(err)
	}
}

func TestNetworkPolicyManagerNFQWSActualResourceReceiptLifecycle(t *testing.T) {
	f := executionNFQWSManagerFixture(t)
	err := f.m.WithExecutionResources(f.ctx, f.p, "nfqws2", func(ctx context.Context) error {
		ctx = f.bind(t, ctx)
		planned := f.latest(t)
		if planned.ResourcePlanID != f.p.PlanID || planned.Resources[0].Phase != "planned" || planned.PlanID == f.p.PlanID {
			t.Fatal("new NFQ check lost original immutable identity", planned)
		}
		if _, err := AcquireNFQWSExecutionResource(ctx, f.spec); err == nil {
			t.Fatal("one live execution reserved the same namespace/queue twice")
		}
		otherQueue := f.spec
		otherQueue.Queue++
		if _, err := AcquireNFQWSExecutionResource(ctx, otherQueue); err == nil {
			t.Fatal("one managed process session acquired a second resource identity")
		}
		effects, _ := f.r.Plan().Effects()
		if err := f.r.ApplyGuard(ctx, f.r.Plan(), effects.Effects[0]); err == nil || len(f.model.calls) != 0 {
			t.Fatal("planned metadata authorized capture", err)
		}
		f.start(t, ctx)
		if err := f.r.ApplyGuard(ctx, f.r.Plan(), effects.Effects[0]); err == nil || len(f.model.calls) != 0 {
			t.Fatal("Start ACK alone authorized capture", err)
		}
		if err := f.r.Prepared(ctx, f.r.Binding()); err != nil {
			t.Fatal(err)
		}
		if f.latest(t).Resources[0].Phase != "capture-ready" {
			t.Fatal("capture grant preceded durable phase")
		}
		foreign := effects.Effects[0]
		foreign.Add = append([]string(nil), foreign.Add...)
		foreign.Add[len(foreign.Add)-1] = "foreign"
		if err := f.r.ApplyGuard(ctx, f.r.Plan(), foreign); err == nil {
			t.Fatal("different effect acquired resource grant")
		}
		if err := f.b.Apply(ctx, f.r.Plan(), f.r.Root()); err != nil {
			t.Fatal(err)
		}
		if err := f.r.SettleRemoved(ctx); err == nil {
			t.Fatal("running child/live capture accepted as removed")
		}
		f.model.running, f.model.stopped = false, true
		if err := f.b.Remove(ctx, f.r.Plan(), f.r.Root()); err != nil {
			t.Fatal(err)
		}
		return f.r.SettleRemoved(ctx)
	})
	if err != nil {
		t.Fatal(err)
	}
	execution := f.latest(t)
	if execution.State != "temporary-complete" || execution.Resources[0].State != "removed" || execution.Resources[0].Phase != "removed" {
		t.Fatal(execution)
	}
	if err := f.r.Current(context.Background(), f.r.Binding()); err == nil {
		t.Fatal("borrowed NFQ callback survived scope close")
	}
	if err := New(f.m.StateRoot).CheckExecutionRecovery(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestNetworkPolicyManagerNFQWSLostStartACKNeverReplays(t *testing.T) {
	f := executionNFQWSManagerFixture(t)
	starts := 0
	err := f.m.WithExecutionResources(f.ctx, f.p, "nfqws2", func(ctx context.Context) error {
		ctx = f.bind(t, ctx)
		if err := f.r.BeforeStart(ctx, f.r.Binding()); err != nil {
			t.Fatal(err)
		}
		bounded, cancel := context.WithTimeout(ctx, 15*time.Second)
		defer cancel()
		begin := func() error { starts++; f.model.running = true; return errors.New("lost actual child Start ACK") }
		if err := f.r.WithStart(bounded, f.r.Binding(), begin); err == nil {
			t.Fatal("lost ACK succeeded")
		}
		if err := f.r.WithStart(bounded, f.r.Binding(), begin); err == nil || starts != 1 {
			t.Fatal("unknown Start replayed", err, starts)
		}
		if err := f.r.Prepared(ctx, f.r.Binding()); err == nil {
			t.Fatal("kernel presence replaced Start ACK")
		}
		return f.b.Apply(ctx, f.r.Plan(), f.r.Root())
	})
	if err == nil || len(f.model.calls) != 0 || f.latest(t).Resources[0].Phase != "closed" {
		t.Fatal("unknown process/capture lost recovery fence", err)
	}
	if err := New(f.m.StateRoot).CheckExecutionRecovery(context.Background()); !errors.Is(err, ErrExecutionJournal) {
		t.Fatal("restart adopted unknown Start", err)
	}
}

func TestNetworkPolicyManagerNFQWSBindingRejectsEveryChangedIdentity(t *testing.T) {
	f := executionNFQWSManagerFixture(t)
	_ = f.m.WithExecutionResources(f.ctx, f.p, "nfqws2", func(ctx context.Context) error {
		ctx = f.bind(t, ctx)
		for field := 0; field < reflect.TypeFor[NFQWSExecutionBinding]().NumField(); field++ {
			changed := f.r.Binding()
			value := reflect.ValueOf(&changed).Elem().Field(field)
			value.SetString(value.String() + "0")
			if err := f.r.BeforeStart(ctx, changed); err == nil {
				t.Fatal("changed process binding admitted", field)
			}
		}
		if len(f.proofs) != 0 || f.latest(t).Resources[0].Phase != "planned" {
			t.Fatal("foreign binding consumed actual owner proof")
		}
		return nil
	})
}

func TestNetworkPolicyManagerNFQWSClosingProofRefusesLateCancellation(t *testing.T) {
	for _, phase := range []nfqwsExecutionReadbackMode{nfqwsExecutionBeforeStart, nfqwsExecutionPrepared} {
		t.Run(string(phase), func(t *testing.T) {
			f := executionNFQWSManagerFixture(t)
			original, cancel := context.WithCancel(f.ctx)
			defer cancel()
			f.onProof = func(mode nfqwsExecutionReadbackMode) {
				if mode == phase {
					cancel()
				}
			}
			err := f.m.WithExecutionResources(original, f.p, "nfqws2", func(ctx context.Context) error {
				ctx = f.bind(t, ctx)
				detached := context.WithoutCancel(ctx)
				if phase == nfqwsExecutionBeforeStart {
					return f.r.BeforeStart(detached, f.r.Binding())
				}
				f.start(t, detached)
				return f.r.Prepared(detached, f.r.Binding())
			})
			if err == nil || len(f.model.calls) != 0 || f.latest(t).Resources[0].Phase != "closed" {
				t.Fatal("late cancellation authorized capture", err)
			}
		})
	}
}

func TestNetworkPolicyManagerNFQWSKnownRemovalSurvivesCancellationAndWANChange(t *testing.T) {
	f := executionNFQWSManagerFixture(t)
	original, cancel := context.WithCancel(f.ctx)
	defer cancel()
	err := f.m.WithExecutionResources(original, f.p, "nfqws2", func(ctx context.Context) error {
		ctx = f.bind(t, ctx)
		f.start(t, ctx)
		if err := f.r.Prepared(ctx, f.r.Binding()); err != nil {
			t.Fatal(err)
		}
		if err := f.b.Apply(ctx, f.r.Plan(), f.r.Root()); err != nil {
			t.Fatal(err)
		}
		cancel()
		f.m.FreshProfile = func(context.Context) (string, error) { return "wan-" + strings.Repeat("f", 12), nil }
		cleanup, stop := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
		defer stop()
		if err := f.b.Apply(cleanup, f.r.Plan(), f.r.Root()); err == nil {
			t.Fatal("detached cancellation resumed capture")
		}
		f.model.running, f.model.stopped = false, true
		if err := f.b.Remove(cleanup, f.r.Plan(), f.r.Root()); err != nil {
			t.Fatal(err)
		}
		return f.r.SettleRemoved(cleanup)
	})
	if err == nil || f.latest(t).Resources[0].State != "removed" {
		t.Fatal("cancelled network request lost exact known cleanup", err)
	}
}

func TestNetworkPolicyManagerNFQWSCloseWaitsForActualStartACK(t *testing.T) {
	f := executionNFQWSManagerFixture(t)
	root := filepath.Join(f.m.StateRoot, "transactions", f.p.PlanID)
	if err := f.m.prepareExecutionRoot(root); err != nil {
		t.Fatal(err)
	}
	execution := Execution{PlanID: f.p.PlanID, Digest: f.p.Digest, State: "applying", StartedAt: time.Now().UTC().Format(time.RFC3339Nano)}
	if err := f.m.writeExecution(root, execution); err != nil {
		t.Fatal(err)
	}
	scope, err := f.m.newExecutionResourceScope(f.ctx, f.p, "nfqws2", &execution, root)
	if err != nil {
		t.Fatal(err)
	}
	defer scope.close()
	ctx := f.bind(t, scope.context())
	if err := f.r.BeforeStart(ctx, f.r.Binding()); err != nil {
		t.Fatal(err)
	}
	bounded, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	entered, ack, started, closed := make(chan struct{}), make(chan struct{}), make(chan error, 1), make(chan error, 1)
	go func() {
		started <- f.r.WithStart(bounded, f.r.Binding(), func() error { close(entered); <-ack; return nil })
	}()
	<-entered
	go func() { closed <- scope.close() }()
	select {
	case err := <-closed:
		t.Fatal("scope closed before actual child ACK", err)
	case <-time.After(20 * time.Millisecond):
	}
	close(ack)
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("Start did not release barrier")
	}
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("close did not join Start ACK")
	}
	if f.latest(t).Resources[0].Phase != "closed" {
		t.Fatal("close failed to fence pending process")
	}
	if err := f.r.WithStart(bounded, f.r.Binding(), func() error { t.Fatal("late Start ran"); return nil }); err == nil {
		t.Fatal("closed scope admitted Start")
	}
	if _, err := os.Stat(filepath.Join(f.r.Root(), policyAdditionFile)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("Start created capture receipt", err)
	}
}

func TestNetworkPolicyManagerNFQWSAdmissionRefusalsPrecedeHelper(t *testing.T) {
	for _, refusal := range []string{"foreign-queue", "missing-owner", "registry-change", "cancelled-start", "unbounded-start", "journal-failure"} {
		t.Run(refusal, func(t *testing.T) {
			f := executionNFQWSManagerFixture(t)
			original, cancel := context.WithCancel(f.ctx)
			defer cancel()
			starts := 0
			_ = f.m.WithExecutionResources(original, f.p, "nfqws2", func(ctx context.Context) error {
				if refusal == "missing-owner" {
					if _, err := AcquireNFQWSExecutionResource(ctx, f.spec); err == nil {
						t.Fatal("issuer accepted missing actual owner producer")
					}
					return nil
				}
				ctx = f.bind(t, ctx)
				switch refusal {
				case "foreign-queue":
					f.model.foreignQueue = true
				case "registry-change":
					if err := f.m.Register(&fakeAdapter{id: "unused"}); err != nil {
						t.Fatal(err)
					}
				case "journal-failure":
					path := filepath.Join(f.m.StateRoot, "latest-execution.json")
					if err := os.Remove(path); err != nil {
						t.Fatal(err)
					}
					if err := os.Mkdir(path, 0700); err != nil {
						t.Fatal(err)
					}
				}
				before := f.r.BeforeStart(ctx, f.r.Binding())
				if refusal == "cancelled-start" {
					cancel()
				}
				bounded, stop := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
				defer stop()
				if refusal == "unbounded-start" {
					bounded = context.WithoutCancel(ctx)
				}
				start := f.r.WithStart(bounded, f.r.Binding(), func() error { starts++; return nil })
				if start == nil {
					t.Fatal("refused owner/context/record admitted helper", refusal, before)
				}
				if refusal == "journal-failure" && len(f.proofs) != 0 {
					t.Fatal("failed process-pending publication reached pre-start readback")
				}
				return start
			})
			if starts != 0 || len(f.model.calls) != 0 {
				t.Fatal("admission refusal produced effects", starts, f.model.calls)
			}
		})
	}
}

func TestNetworkPolicyManagerNFQWSPreparedFailureCannotRenewStart(t *testing.T) {
	f := executionNFQWSManagerFixture(t)
	starts := 0
	_ = f.m.WithExecutionResources(f.ctx, f.p, "nfqws2", func(ctx context.Context) error {
		ctx = f.bind(t, ctx)
		if err := f.r.BeforeStart(ctx, f.r.Binding()); err != nil {
			t.Fatal(err)
		}
		bounded, cancel := context.WithTimeout(ctx, time.Second)
		defer cancel()
		begin := func() error { starts++; return nil } // ACK model with no running child.
		if err := f.r.WithStart(bounded, f.r.Binding(), begin); err != nil {
			t.Fatal(err)
		}
		if err := f.r.Prepared(ctx, f.r.Binding()); err == nil {
			t.Fatal("Start ACK replaced fresh live process/queue proof")
		}
		f.model.running = true
		if err := f.r.Prepared(ctx, f.r.Binding()); err == nil {
			t.Fatal("failed original prepared observation was retried")
		}
		if err := f.r.WithStart(bounded, f.r.Binding(), begin); err == nil || starts != 1 {
			t.Fatal("failed prepared check renewed process Start", err)
		}
		effects, _ := f.r.Plan().Effects()
		return f.r.ApplyGuard(ctx, f.r.Plan(), effects.Effects[0])
	})
	if len(f.model.calls) != 0 || f.latest(t).Resources[0].Phase != "closed" {
		t.Fatal("failed live proof allowed capture")
	}
}

func TestNetworkPolicyManagerNFQWSPanicReleasesStartBarrierAndFences(t *testing.T) {
	f := executionNFQWSManagerFixture(t)
	func() {
		defer func() {
			if recover() != "actual Start panic" {
				t.Fatal("Start panic was not preserved")
			}
		}()
		_ = f.m.WithExecutionResources(f.ctx, f.p, "nfqws2", func(ctx context.Context) error {
			ctx = f.bind(t, ctx)
			if err := f.r.BeforeStart(ctx, f.r.Binding()); err != nil {
				t.Fatal(err)
			}
			bounded, cancel := context.WithTimeout(ctx, time.Second)
			defer cancel()
			return f.r.WithStart(bounded, f.r.Binding(), func() error { panic("actual Start panic") })
		})
	}()
	if !f.r.scope.startMu.TryLock() {
		t.Fatal("panic leaked close barrier")
	}
	f.r.scope.startMu.Unlock()
	if f.latest(t).Resources[0].Phase != "closed" {
		t.Fatal("panic lost unfinished process intent")
	}
	if err := New(f.m.StateRoot).CheckExecutionRecovery(context.Background()); !errors.Is(err, ErrExecutionJournal) {
		t.Fatal("panic cleared restart fence", err)
	}
}

func TestNetworkPolicyManagerNFQWSLateCurrentRefusesChangedWANAndRegistry(t *testing.T) {
	for _, change := range []string{"WAN", "registry"} {
		t.Run(change, func(t *testing.T) {
			f := executionNFQWSManagerFixture(t)
			_ = f.m.WithExecutionResources(f.ctx, f.p, "nfqws2", func(ctx context.Context) error {
				ctx = f.bind(t, ctx)
				if err := f.r.BeforeStart(ctx, f.r.Binding()); err != nil {
					t.Fatal(err)
				}
				if change == "WAN" {
					f.m.FreshProfile = func(context.Context) (string, error) { return "wan-" + strings.Repeat("f", 12), nil }
				} else if err := f.m.Register(&fakeAdapter{id: "late-unused"}); err != nil {
					t.Fatal(err)
				}
				// The actual parent must perform this late live check after READY,
				// before sending PERMIT. Control/files proof alone is insufficient.
				if err := f.r.Current(ctx, f.r.Binding()); err == nil {
					t.Fatal("stale review reached late launch boundary")
				}
				bounded, cancel := context.WithTimeout(ctx, time.Second)
				defer cancel()
				return f.r.WithStart(bounded, f.r.Binding(), func() error { t.Fatal("stale network/registry started helper"); return nil })
			})
			if f.latest(t).Resources[0].Phase != "closed" {
				t.Fatal("late live proof did not retain pending fence")
			}
		})
	}
}
