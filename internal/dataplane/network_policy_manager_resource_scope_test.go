package dataplane

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

// The actual issuer/compiler/common receipt and private owner readback run
// against the existing explicit IP/boot/source model. This is no native proof.
type executionResourceFixture struct {
	m            *Manager
	p            Plan
	lease        *nodeTransitLease
	runner       *nodeTransitTestRunner
	authority    *nodeTransitAuthority
	readback     *nodeRouterTransitReadback
	registration nodeTransitRegistration
	ctx          context.Context
}

func executionResourceManagerFixture(t *testing.T) *executionResourceFixture {
	t.Helper()
	l, runner, authority := nodeTransitFixture(t)
	m := New(privateScopedXrayFixtureDir(t))
	m.FreshProfile = func(context.Context) (string, error) { return l.spec.NetworkProfile, nil }
	if err := m.Register(&fakeAdapter{id: l.spec.Engine}); err != nil {
		t.Fatal(err)
	}
	p := Plan{SchemaVersion: SchemaVersion, PlanID: l.spec.PlanID, Digest: l.spec.PlanDigest, NetworkProfileID: l.spec.NetworkProfile,
		Ready: true, Adapters: []string{l.spec.Engine}, State: "committed"}
	if err := m.recordLocked(p); err != nil {
		t.Fatal(err)
	}
	return &executionResourceFixture{m: m, p: p, lease: l, runner: runner, authority: authority,
		ctx: WithReviewGuard(context.Background(), func(c context.Context) error { return c.Err() })}
}

func (f *executionResourceFixture) bind(t *testing.T, ctx context.Context) context.Context {
	t.Helper()
	f.readback = &nodeRouterTransitReadback{spec: f.lease.spec, owner: func(c context.Context) error {
		return f.lease.runtime.guard(c, f.lease.spec)
	}}
	ctx = context.WithValue(ctx, networkPolicyTransitReadbackKey{}, networkPolicyTransitReadback(f.readback.readback))
	issuer, ok := ctx.Value(nodeTransitRegistrarKey{}).(nodeTransitRegistrar)
	if !ok {
		t.Fatal("actual Manager did not supply issuer")
	}
	registration, err := issuer(ctx, f.lease.spec)
	if err != nil {
		t.Fatal(err)
	}
	f.registration = registration
	f.lease.root = registration.root
	f.lease.runtime.register = registration.register
	f.readback.root = registration.root
	f.readback.info, err = os.Lstat(registration.root)
	if err != nil {
		t.Fatal(err)
	}
	f.readback.lease = f.lease
	return ctx
}

func (f *executionResourceFixture) latest(t *testing.T) Execution {
	t.Helper()
	var execution *Execution
	if found, err := readOptionalJournal(filepath.Join(f.m.StateRoot, "latest-execution.json"), &execution); err != nil || !found {
		t.Fatal("missing existing journal", err)
	}
	return *execution
}

func (f *executionResourceFixture) remove(ctx context.Context) error {
	if err := f.lease.Remove(ctx); err != nil {
		return err
	}
	return f.registration.settle(ctx, f.lease.spec, f.registration.root, f.lease.digest)
}

func TestNetworkPolicyManagerResourceIssuerDurableBeforeEffectsAndReadbackSettlement(t *testing.T) {
	f := executionResourceManagerFixture(t)
	err := f.m.WithExecutionResources(f.ctx, f.p, "xray", func(ctx context.Context) error {
		ctx = f.bind(t, ctx)
		before := f.latest(t)
		if len(before.Resources) != 0 {
			t.Fatal("allocation itself registered intent")
		}
		owner := f.readback.owner
		f.readback.owner = func(c context.Context) error {
			e := f.latest(t)
			if len(e.Resources) != 1 || e.Resources[0].State != "prepared" || f.runner.adds != 0 {
				t.Fatal("prepared owner readback preceded durable registration")
			}
			// Read-only owner/consumer guards may reenter the registrar. Actual
			// readback must not execute while holding its metadata mutex.
			return errors.Join(owner(c), f.registration.cleanupGuard(c))
		}
		if err := f.lease.Apply(ctx); err != nil {
			return err
		}
		f.readback.owner = owner
		// Exact absence alone does not settle: the real common receipt still
		// names an active add acknowledgement.
		f.runner.rules[4] = nil
		if err := f.registration.settle(ctx, f.lease.spec, f.registration.root, f.lease.digest); err == nil {
			t.Fatal("absence without removed receipt settled metadata")
		}
		f.runner.rules[4] = []string{f.runner.line()}
		return f.remove(ctx)
	})
	if err != nil || f.runner.adds != 1 || f.runner.deletes != 1 {
		t.Fatal("actual temporary transaction", err, f.runner.adds, f.runner.deletes)
	}
	e := f.latest(t)
	if e.PlanID == f.p.PlanID || e.ResourcePlanID != f.p.PlanID || e.Digest != f.p.Digest || e.State != "temporary-complete" || e.Resources[0].State != "removed" {
		t.Fatal("original plan identity or settled outcome changed", e)
	}
	committed, exists, err := f.m.Committed()
	if err != nil || !exists || !reflect.DeepEqual(committed, f.p) {
		t.Fatal("temporary check changed committed plan", committed, err)
	}
	if err := New(f.m.StateRoot).CheckExecutionRecovery(context.Background()); err != nil {
		t.Fatal("known settlement remained fenced", err)
	}
	for _, call := range []func() error{
		func() error { return f.registration.register(f.ctx, f.lease.spec, f.registration.root, f.lease.digest) },
		func() error { return f.registration.settle(f.ctx, f.lease.spec, f.registration.root, f.lease.digest) },
		func() error { return f.registration.cleanupGuard(f.ctx) },
	} {
		if err := call(); err == nil {
			t.Fatal("closed operation retained authority")
		}
	}
}

func TestNetworkPolicyManagerResourcePendingAndLostACKFenceRestart(t *testing.T) {
	for _, loseACK := range []bool{false, true} {
		t.Run(map[bool]string{false: "omitted cleanup", true: "lost add acknowledgement"}[loseACK], func(t *testing.T) {
			f := executionResourceManagerFixture(t)
			f.runner.loseAddACK = loseACK
			err := f.m.WithExecutionResources(f.ctx, f.p, "xray", func(ctx context.Context) error {
				ctx = f.bind(t, ctx)
				return f.lease.Apply(ctx)
			})
			if !errors.Is(err, ErrExecutionJournal) || f.runner.adds != 1 || f.runner.deletes != 0 {
				t.Fatal("unknown resource escaped operation", err)
			}
			e := f.latest(t)
			if e.State != "resource-failed" || len(e.Resources) != 1 || e.Resources[0].State != "prepared" {
				t.Fatal("pending intent lost", e)
			}
			if err := New(f.m.StateRoot).CheckExecutionRecovery(context.Background()); !errors.Is(err, ErrExecutionJournal) {
				t.Fatal("restart adopted pending resource", err)
			}
			called := false
			if err := f.m.WithExecutionResources(f.ctx, f.p, "xray", func(context.Context) error { called = true; return nil }); err == nil || called {
				t.Fatal("new resource operation passed recovery fence", err)
			}
		})
	}
}

func TestNetworkPolicyManagerResourceUnusedRequiresOriginalProofAndMatchingRecord(t *testing.T) {
	f := executionResourceManagerFixture(t)
	f.authority.preflightErr = errors.New("fixture refused before common writer")
	err := f.m.WithExecutionResources(f.ctx, f.p, "xray", func(ctx context.Context) error {
		ctx = f.bind(t, ctx)
		applyErr := f.lease.Apply(ctx)
		if !isNodeTransitBeforeEffects(applyErr) || f.runner.adds != 0 {
			t.Fatal("missing actual before-effects classification", applyErr)
		}
		if err := f.registration.settleUnused(ctx, f.lease.spec, f.registration.root, f.lease.digest); err == nil {
			t.Fatal("unverified live error settled resource")
		}
		if err := f.lease.VerifyUnused(ctx); err != nil {
			return err
		}
		if !errors.As(applyErr, &f.readback.unused) {
			t.Fatal("original private error lost")
		}
		wrong := f.lease.spec
		wrong.IfIndex++
		if err := f.registration.settleUnused(ctx, wrong, f.registration.root, f.lease.digest); err == nil {
			t.Fatal("foreign record spent actual unused proof")
		}
		if err := f.registration.settleUnused(ctx, f.lease.spec, f.registration.root, f.lease.digest); err != nil {
			return err
		}
		if err := f.registration.settleUnused(ctx, f.lease.spec, f.registration.root, f.lease.digest); err == nil {
			t.Fatal("unused settlement replayed")
		}
		return nil
	})
	if err != nil || f.latest(t).Resources[0].State != "unused" || f.runner.deletes != 0 {
		t.Fatal("known unused settlement", err)
	}
}

func TestNetworkPolicyManagerResourceCancellationAndWANChangePermitExactCleanup(t *testing.T) {
	f := executionResourceManagerFixture(t)
	parent, cancel := context.WithCancel(f.ctx)
	err := f.m.WithExecutionResources(parent, f.p, "xray", func(ctx context.Context) error {
		ctx = f.bind(t, ctx)
		if err := f.lease.Apply(ctx); err != nil {
			return err
		}
		cancel()
		f.m.FreshProfile = func(context.Context) (string, error) { return "wan-ffffffffffff", nil }
		cleanup, cleanupCancel := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
		defer cleanupCancel()
		issuer := cleanup.Value(nodeTransitRegistrarKey{}).(nodeTransitRegistrar)
		if _, err := issuer(cleanup, f.lease.spec); !errors.Is(err, context.Canceled) {
			t.Fatal("cancel detachment retained forward admission", err)
		}
		// Only the actual Remove entry point can mark its registration as
		// cleanup. Apply must mask an inherited private removal marker.
		if err := f.lease.Apply(context.WithValue(cleanup, nodeTransitRemovalKey{}, true)); err == nil || f.runner.adds != 1 {
			t.Fatal("repeated Apply borrowed cleanup authority", err)
		}
		if err := f.registration.register(cleanup, f.lease.spec, f.registration.root, f.lease.digest); !errors.Is(err, context.Canceled) {
			t.Fatal("forward registration renewed cancelled operation", err)
		}
		if err := f.registration.cleanupGuard(cleanup); err != nil {
			return err
		}
		return f.remove(cleanup)
	})
	if err == nil || f.latest(t).Resources[0].State != "removed" || f.runner.deletes != 1 {
		t.Fatal("cancelled forward path blocked owned cleanup", err)
	}
	if err := New(f.m.StateRoot).CheckExecutionRecovery(context.Background()); err != nil {
		t.Fatal("fully removed cancelled check stayed fenced", err)
	}
}

func TestNetworkPolicyManagerResourceWANChangeRefusesForwardButAllowsKnownRemoval(t *testing.T) {
	f := executionResourceManagerFixture(t)
	err := f.m.WithExecutionResources(f.ctx, f.p, "xray", func(ctx context.Context) error {
		ctx = f.bind(t, ctx)
		if err := f.lease.Apply(ctx); err != nil {
			return err
		}
		f.m.FreshProfile = func(context.Context) (string, error) { return "wan-ffffffffffff", nil }
		if err := f.registration.register(ctx, f.lease.spec, f.registration.root, f.lease.digest); !errors.Is(err, ErrNetworkChanged) {
			t.Fatal("forward register ignored WAN change", err)
		}
		return f.remove(ctx)
	})
	if err != nil || f.runner.adds != 1 || f.runner.deletes != 1 || f.latest(t).Resources[0].State != "removed" {
		t.Fatal("fresh-forward/owned-cleanup authority mixed", err)
	}
}

func TestNetworkPolicyManagerResourceRegistryChangeRevokesScope(t *testing.T) {
	f := executionResourceManagerFixture(t)
	err := f.m.WithExecutionResources(f.ctx, f.p, "xray", func(ctx context.Context) error {
		ctx = f.bind(t, ctx)
		if err := f.m.Register(&fakeAdapter{id: "nfqws2"}); err != nil {
			return err
		}
		if err := f.registration.register(ctx, f.lease.spec, f.registration.root, f.lease.digest); err == nil {
			t.Fatal("changed registry retained resource authority")
		}
		return nil
	})
	if err != nil || f.runner.adds != 0 || len(f.latest(t).Resources) != 0 {
		t.Fatal("registry change granted effects", err)
	}
}

func TestNetworkPolicyManagerResourceJournalFailurePrecedesEffects(t *testing.T) {
	f := executionResourceManagerFixture(t)
	err := f.m.WithExecutionResources(f.ctx, f.p, "xray", func(ctx context.Context) error {
		ctx = f.bind(t, ctx)
		path := filepath.Join(f.m.StateRoot, "latest-execution.json")
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(path, 0700); err != nil {
			t.Fatal(err)
		}
		return f.lease.Apply(ctx)
	})
	if !errors.Is(err, ErrExecutionJournal) || f.runner.adds != 0 || f.runner.deletes != 0 {
		t.Fatal("journal failure entered common effect writer", err)
	}
}

type executionResourceGateConsumer struct {
	*networkPolicyGateConsumer
	fixture *executionResourceFixture
	t       *testing.T
}

func (a *executionResourceGateConsumer) Health(ctx context.Context, p Plan, _ string) error {
	f := a.fixture
	spec := f.lease.spec
	spec.PlanID, spec.PlanDigest, spec.NetworkProfile = p.PlanID, p.Digest, p.NetworkProfileID
	f.authority.spec, f.runner.spec = spec, spec
	lease, err := newNodeTransitLeaseWithOptions(spec, f.lease.root, f.lease.runtime, f.lease.options)
	if err != nil {
		return err
	}
	f.lease, f.p = lease, p
	return lease.Apply(f.bind(a.t, ctx)) // Intentionally omit actual cleanup.
}

func TestNetworkPolicyManagerResourceUnknownHoldsLANDespiteConsumerRollbackProof(t *testing.T) {
	m, p, gate, _, model := networkPolicyGateManagerFixture(t)
	f := executionResourceManagerFixture(t)
	f.m = m
	consumer := &executionResourceGateConsumer{networkPolicyGateConsumer: &networkPolicyGateConsumer{
		fakeAdapter: &fakeAdapter{id: "xray"}, gate: gate, proof: true}, fixture: f, t: t}
	if err := m.Register(consumer); err != nil {
		t.Fatal(err)
	}
	gate.Binding.RetireCheck = func(context.Context, *LANPolicyRuntimePlan) error {
		if consumer.live {
			return ErrNetworkPolicyConsumers
		}
		return nil
	}
	p, err := BuildAt(Input{LAN: p.LAN, NetworkProfileID: p.NetworkProfileID, Revision: p.Revision,
		Routes: []Route{{ServiceID: "network-cell", LogicalServiceID: "default", Resolved: "xray", Sources: []string{"192.168.1.0/24"},
			Ingress: []string{"br0"}, CIDRs: []string{"8.8.8.0/24"}, NetworkPolicyGeneration: p.LAN.Generation, NetworkPolicyRole: "default"}},
		Engines: []Engine{{ID: NetworkPolicyAdapterID, Installed: true, Configured: true, Activatable: true}, {ID: "xray", Installed: true, Configured: true, Activatable: true}},
		Host:    HostState{IPCommand: true, IPTables: true, IP6Tables: true, TUN: true, SingBox: true}}, time.Unix(101, 0))
	if err != nil || !p.Ready {
		t.Fatal("actual scoped fixture plan", err, p.Blockers)
	}
	committed := false
	execution, err := m.Apply(f.ctx, p, func() (func() error, error) { committed = true; return nil, nil })
	if !errors.Is(err, ErrExecutionJournal) || execution.State != "rollback-failed" || execution.RollbackVerified || committed || !consumer.verified {
		t.Fatal("resource fence ignored known consumer rollback", execution, err)
	}
	if len(execution.Resources) != 1 || execution.Resources[0].State != "prepared" {
		t.Fatal("temporary intent lost from SAME Apply execution", execution)
	}
	if state, err := gate.readOwner(); err != nil || state == nil {
		t.Fatal("unknown resource withdrew LAN boundary", state, err)
	}
	present := false
	for _, count := range model.present {
		present = present || count > 0
	}
	if !present || f.runner.adds != 1 || f.runner.deletes != 0 {
		t.Fatal("unknown transit or LAN boundary disappeared")
	}
}

func TestNetworkPolicyManagerResourceRefusesMissingReadbackAndFreshNetwork(t *testing.T) {
	for _, mode := range []string{"readback", "network", "review"} {
		t.Run(mode, func(t *testing.T) {
			f := executionResourceManagerFixture(t)
			if mode == "review" {
				f.ctx = context.Background()
			}
			err := f.m.WithExecutionResources(f.ctx, f.p, "xray", func(ctx context.Context) error {
				if mode == "network" {
					f.m.FreshProfile = nil
					ctx = context.WithValue(ctx, networkPolicyTransitReadbackKey{}, networkPolicyTransitReadback(func(context.Context, NodeTransitSpec, string, string, networkPolicyTransitReadbackMode) error {
						return nil
					}))
				}
				issuer := ctx.Value(nodeTransitRegistrarKey{}).(nodeTransitRegistrar)
				_, err := issuer(ctx, f.lease.spec)
				return err
			})
			if err == nil || f.runner.adds != 0 {
				t.Fatal("missing concrete admission was granted", err)
			}
		})
	}
}

func TestNetworkPolicyManagerResourceUnexpectedExitRevokesBorrowedAuthority(t *testing.T) {
	for _, where := range []string{"action", "authority"} {
		t.Run(where, func(t *testing.T) {
			f := executionResourceManagerFixture(t)
			panicGuard := false
			f.ctx = WithReviewGuard(context.Background(), func(c context.Context) error {
				if panicGuard {
					panic("fixture authority interrupted")
				}
				return c.Err()
			})
			func() {
				defer func() {
					if recover() == nil {
						t.Fatal("fixture did not interrupt action")
					}
				}()
				_ = f.m.WithExecutionResources(f.ctx, f.p, "xray", func(ctx context.Context) error {
					ctx = f.bind(t, ctx)
					panicGuard = where == "authority"
					if err := f.lease.Apply(ctx); err != nil {
						return err
					}
					panic("fixture action interrupted")
				})
			}()
			if err := f.registration.cleanupGuard(context.Background()); err == nil {
				t.Fatal("unexpected exit retained scope authority")
			}
			if err := New(f.m.StateRoot).CheckExecutionRecovery(context.Background()); !errors.Is(err, ErrExecutionJournal) {
				t.Fatal("unexpected exit published completion", err)
			}
		})
	}
}

func TestNetworkPolicyManagerResourceLateReadbackCannotGrantEffects(t *testing.T) {
	f := executionResourceManagerFixture(t)
	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	err := f.m.WithExecutionResources(f.ctx, f.p, "xray", func(ctx context.Context) error {
		ctx = f.bind(t, ctx)
		owner := f.readback.owner
		f.readback.owner = func(c context.Context) error {
			close(entered)
			<-release
			return owner(c)
		}
		go func() { done <- f.lease.Apply(ctx) }()
		<-entered
		return nil // A borrower that was not joined cannot keep the scope open.
	})
	close(release)
	select {
	case borrowerErr := <-done:
		if borrowerErr == nil {
			t.Fatal("late readback acquired effect authority")
		}
	case <-time.After(time.Second):
		t.Fatal("closed borrower did not finish")
	}
	if !errors.Is(err, ErrExecutionJournal) || f.runner.adds != 0 || f.latest(t).Resources[0].State != "prepared" {
		t.Fatal("late borrower escaped retained fence", err)
	}
}
