package dataplane

import (
	"context"
	"errors"
	"testing"
)

func nodeTransitPolicyRuntimeFixture(t *testing.T, check func(context.Context, NodeTransitSpec) error) (*nodeTransitLease, *nodeTransitTestRunner, PolicyEffectRuntime, *nodeTransitPolicyRuntimeOrigin) {
	t.Helper()
	base, runner, _ := nodeTransitFixture(t)
	if check == nil {
		check = func(context.Context, NodeTransitSpec) error { return nil }
	}
	owner := newNodeTransitSharedOwner(base.spec, base.root, check)
	l, err := newNodeTransitLeaseWithOptions(base.spec, base.root, nodeTransitRuntime{runner: runner, ip: "ip", sharedOwner: owner, register: base.runtime.register}, base.options)
	if err != nil {
		t.Fatal(err)
	}
	origin := newNodeTransitPolicyRuntimeOrigin(l)
	return l, runner, PolicyEffectRuntime{Runner: runner, Tools: PolicyEffectTools{IP: "ip"}, nodeTransitOrigin: origin}, origin
}

func TestNodeTransitPolicyRuntimeConstructorSealsOriginalRoles(t *testing.T) {
	checks := 0
	l, runner, bare, origin := nodeTransitPolicyRuntimeFixture(t, func(context.Context, NodeTransitSpec) error { checks++; return nil })
	internal, binding, err := normalizeNodeTransitPolicyRuntime(origin, bare, l.plan, l.root)
	if err != nil || binding == nil || internal.nodeTransitOrigin != nil || internal.Guard == nil || internal.ExactPresence == nil || internal.Preflight == nil || internal.BeforeDelete == nil || len(runner.calls) != 0 || checks != 0 {
		t.Fatal("constructor changed callback/effect boundary", err, checks, runner.calls)
	}
	if count, err := binding.presence(context.Background(), l.plan, l.root, 0); err != nil || count != 0 || checks != 2 || runner.adds != 0 || runner.deletes != 0 {
		t.Fatal("lost actual full guarded BOTH-family read", count, err, checks)
	}
	if _, _, err := normalizeNodeTransitPolicyRuntime(origin, internal, l.plan, l.root); err == nil {
		t.Fatal("internally filled callbacks replayed as opt-in")
	}
}

func TestNodeTransitPolicyRuntimeRejectsMixedAndChangedInputsBeforeCallbacks(t *testing.T) {
	for _, name := range []string{"guard", "presence", "preflight", "delete", "runner", "tool", "extra-tool", "root", "plan", "origin-copy", "lease-copy", "owner-copy"} {
		t.Run(name, func(t *testing.T) {
			checks := 0
			l, runner, bare, origin := nodeTransitPolicyRuntimeFixture(t, func(context.Context, NodeTransitSpec) error { checks++; return nil })
			plan, root := l.plan, l.root
			switch name {
			case "guard":
				bare.Guard = func(context.Context, int) error { t.Fatal("mixed guard invoked"); return nil }
			case "presence":
				bare.ExactPresence = func(context.Context, int) (int, error) { t.Fatal("mixed reader invoked"); return 0, nil }
			case "preflight":
				bare.Preflight = func(context.Context) error { t.Fatal("mixed preflight invoked"); return nil }
			case "delete":
				bare.BeforeDelete = func(context.Context, int) error { t.Fatal("mixed delete invoked"); return nil }
			case "runner":
				bare.Runner = &nodeTransitTestRunner{}
			case "tool":
				bare.Tools.IP = "foreign-ip"
			case "extra-tool":
				bare.Tools.IPTables = "iptables"
			case "root":
				root += "-foreign"
			case "plan":
				plan, _, _ = copyPolicyEffectPlan(plan)
				plan.Effects[0].Add[2] = "del"
			case "origin-copy":
				origin = &nodeTransitPolicyRuntimeOrigin{self: origin, lease: l}
			case "lease-copy":
				origin.lease = &nodeTransitLease{spec: l.spec, root: l.root, plan: l.plan, runtime: l.runtime}
			case "owner-copy":
				o := l.runtime.sharedOwner
				l.runtime.sharedOwner = &nodeTransitSharedOwner{self: o, spec: o.spec, root: o.root, check: o.check}
			}
			if _, _, err := normalizeNodeTransitPolicyRuntime(origin, bare, plan, root); err == nil || checks != 0 || len(runner.calls) != 0 {
				t.Fatal("foreign input invoked callback or gained binding", err, checks, runner.calls)
			}
		})
	}
}

func TestNodeTransitPolicyRuntimeBindingCannotBeReplacedByPublicCallbacks(t *testing.T) {
	failure := errors.New("actual original owner changed")
	l, runner, bare, origin := nodeTransitPolicyRuntimeFixture(t, func(context.Context, NodeTransitSpec) error { return failure })
	internal, binding, err := normalizeNodeTransitPolicyRuntime(origin, bare, l.plan, l.root)
	if err != nil {
		t.Fatal(err)
	}
	// Mutating a caller-owned runtime copy cannot change the separate original
	// guarded presence reader retained separately by the original session.
	internal.Guard = func(context.Context, int) error { return nil }
	internal.ExactPresence = func(context.Context, int) (int, error) { return 0, nil }
	if _, err := binding.presence(context.Background(), l.plan, l.root, 0); !errors.Is(err, failure) || len(runner.calls) != 0 {
		t.Fatal("public callbacks bypassed original owner", err, runner.calls)
	}
	copy := &nodeTransitPolicyRuntimeBinding{self: binding, origin: binding.origin, plan: binding.plan, root: binding.root}
	if _, err := copy.presence(context.Background(), l.plan, l.root, 0); err == nil {
		t.Fatal("copied binding accepted")
	}
}

type nonComparableNodeTransitRunner []byte

func (nonComparableNodeTransitRunner) Run(context.Context, string, ...string) ([]byte, error) {
	return nil, errors.New("must not run")
}

func TestNodeTransitPolicyRuntimeRunnerComparisonRefusesNonComparableAndNil(t *testing.T) {
	var nilPointer *nodeTransitTestRunner
	if sameNodeTransitPolicyRunner(nonComparableNodeTransitRunner{1}, nonComparableNodeTransitRunner{1}) || sameNodeTransitPolicyRunner(nilPointer, nilPointer) || sameNodeTransitPolicyRunner(nil, nil) {
		t.Fatal("invalid exact runner comparison")
	}
}

func TestNodeTransitPolicyRuntimeBindingKeepsFreshContextAndPlanChecks(t *testing.T) {
	checks := 0
	l, runner, bare, origin := nodeTransitPolicyRuntimeFixture(t, func(context.Context, NodeTransitSpec) error { checks++; return nil })
	_, binding, err := normalizeNodeTransitPolicyRuntime(origin, bare, l.plan, l.root)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := binding.presence(ctx, l.plan, l.root, 0); !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation cause lost", err)
	}
	for _, test := range []struct {
		ctx   context.Context
		root  string
		index int
	}{{nil, l.root, 0}, {context.Background(), l.root + "-foreign", 0}, {context.Background(), l.root, 1}} {
		if _, err := binding.presence(test.ctx, l.plan, test.root, test.index); err == nil {
			t.Fatal("foreign comparison accepted")
		}
	}
	// The constructor copied expected intent. A later mutation of the caller's
	// original plan cannot silently become the bound session's new intent.
	l.plan.Effects[0].Add[2] = "del"
	if _, err := binding.presence(context.Background(), l.plan, l.root, 0); err == nil || checks != 0 || len(runner.calls) != 0 {
		t.Fatal("changed plan invoked an original read", err, checks, runner.calls)
	}
}
