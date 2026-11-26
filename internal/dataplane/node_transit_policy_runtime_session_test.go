package dataplane

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// Actual receipt/session IO with modeled kernel commands. These tests do not
// claim native routing, a real component owner or packet acceptance.
func TestNodeTransitPolicyRuntimeMixedSessionCreatesNoLockOrReceipt(t *testing.T) {
	for _, name := range []string{"guard", "presence", "preflight", "delete", "runner", "tool", "plan", "root", "copied-origin", "copied-owner", "copied-lease"} {
		t.Run(name, func(t *testing.T) {
			l, runner, bare, origin := nodeTransitPolicyRuntimeFixture(t, nil)
			plan, root := l.plan, l.root
			switch name {
			case "guard":
				bare.Guard = func(context.Context, int) error { t.Fatal("mixed callback ran"); return nil }
			case "presence":
				bare.ExactPresence = func(context.Context, int) (int, error) { t.Fatal("mixed callback ran"); return 0, nil }
			case "preflight":
				bare.Preflight = func(context.Context) error { t.Fatal("mixed callback ran"); return nil }
			case "delete":
				bare.BeforeDelete = func(context.Context, int) error { t.Fatal("mixed callback ran"); return nil }
			case "runner":
				bare.Runner = &nodeTransitTestRunner{}
			case "tool":
				bare.Tools.IP = "foreign-ip"
			case "plan":
				plan, _, _ = copyPolicyEffectPlan(plan)
				plan.Effects[0].Add[2] = "del"
			case "root":
				root = filepath.Join(l.root, "not-created")
			case "copied-origin":
				bare.nodeTransitOrigin = &nodeTransitPolicyRuntimeOrigin{self: origin, lease: l}
			case "copied-owner":
				o := l.runtime.sharedOwner
				l.runtime.sharedOwner = &nodeTransitSharedOwner{self: o, spec: o.spec, root: o.root, check: o.check}
				bare = l.policyEffectRuntime()
			case "copied-lease":
				copy := &nodeTransitLease{spec: l.spec, plan: l.plan, root: l.root, runtime: l.runtime}
				bare = copy.policyEffectRuntime()
			}
			if err := applyPolicyEffects(context.Background(), bare, plan, root, policyAdditionOptions{boot: l.options.boot}); err == nil || len(runner.calls) != 0 {
				t.Fatal("mixed session obtained IO/effect", err, runner.calls)
			}
			for _, name := range []string{policyAdditionFile, policyAdditionLock} {
				if _, err := os.Lstat(filepath.Join(root, name)); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("mixed runtime created session artifact", name, err)
				}
			}
		})
	}
}

func TestNodeTransitPolicyRuntimeSessionKeepsClosingFailureUnknown(t *testing.T) {
	intent, read := false, false
	failure := errors.New("original closing owner changed")
	l, runner, bare, _ := nodeTransitPolicyRuntimeFixture(t, func(context.Context, NodeTransitSpec) error {
		if intent && read {
			return failure
		}
		return nil
	})
	runner.beforeRead = func(_ context.Context, family int) error {
		if intent && family == 6 {
			read = true
		}
		return nil
	}
	err := applyPolicyEffects(context.Background(), bare, l.plan, l.root, policyAdditionOptions{boot: l.options.boot, fault: func(phase string, _ int) error {
		if phase == "intent" {
			intent = true
		}
		return nil
	}})
	if !errors.Is(err, failure) || !errors.Is(err, ErrPolicyAdditionUnknown) || runner.adds != 0 {
		t.Fatal("closing failure became RPC or lost unknown fence", err, runner.adds)
	}
	status, inspectErr := l.Inspect(context.Background())
	if inspectErr != nil || !status.Unknown || status.Complete {
		t.Fatal("durable intent lost unknown status", status, inspectErr)
	}
}

func TestNodeTransitPolicyRuntimeSessionCancellationAfterPresenceRefusesBeforeStart(t *testing.T) {
	checks := 0
	l, runner, bare, _ := nodeTransitPolicyRuntimeFixture(t, func(context.Context, NodeTransitSpec) error { checks++; return nil })
	internal, binding, err := preparePolicyEffectRuntime(bare, l.plan, l.root)
	if err != nil {
		t.Fatal(err)
	}
	s, err := openPolicyEffectSession(context.Background(), l.plan, l.root, policyAdditionOptions{boot: l.options.boot})
	if err != nil {
		t.Fatal(err)
	}
	defer s.close()
	s.nodeTransitPresence = binding
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if count, err := s.exactPresence(ctx, internal, 0); err != nil || count != 0 {
		t.Fatal(count, err)
	}
	cancel() // No callback/effect is inserted into the production call graph.
	if err := s.guardAfterPresence(ctx, internal, 0); !errors.Is(err, context.Canceled) || checks != 2 || runner.adds != 0 {
		t.Fatal("expired presence reached command-start boundary", err, checks, runner.adds)
	}
}

func TestNodeTransitPolicyRuntimeSessionOnlyRemovesTwoAdjacentChecks(t *testing.T) {
	counts := make([]int, 2)
	commands := make([][]string, 2)
	for mode := range 2 {
		checks := 0
		l, runner, bare, _ := nodeTransitPolicyRuntimeFixture(t, func(context.Context, NodeTransitSpec) error { checks++; return nil })
		runtime := l.effectRuntime()
		if mode == 1 {
			runtime = bare
		}
		if err := applyPolicyEffects(context.Background(), runtime, l.plan, l.root, policyAdditionOptions{boot: l.options.boot}); err != nil || runner.adds != 1 {
			t.Fatal("actual modeled session failed", mode, err, runner.adds)
		}
		status, err := l.Inspect(context.Background())
		if err != nil || !status.Complete || status.Unknown {
			t.Fatal("session lost complete receipt", status, err)
		}
		counts[mode], commands[mode] = checks, append([]string(nil), runner.calls...)
	}
	if counts[0]-counts[1] != 2 || !reflect.DeepEqual(commands[0], commands[1]) {
		t.Fatal("changed reads/effects or removed non-adjacent guards", counts, commands)
	}
}
