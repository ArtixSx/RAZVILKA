package dataplane

import (
	"context"
	"errors"
	"testing"
)

// Real COMMON writer/publication, modeled kernel. The native LAN gate remains
// responsible for original process, queue, complete inventory and settlement.
func TestNFQWSScopedIssuedBoundaryPreservesNeverIssuedCustody(t *testing.T) {
	for _, cut := range []string{"guard", "cancel", "base-refusal", "lost-ACK"} {
		t.Run(cut, func(t *testing.T) {
			b, model, root := nfqwsScopedBindingFixture(t)
			runtime, plan, err := b.prepare(model.p, false)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			failure := errors.New("closed boundary test refusal")
			baseCalls := 0
			base := runtime.Runner
			runner := nfqwsScopedApplyRunner{base: networkCleanupRunner(func(c context.Context, command string, args ...string) ([]byte, error) {
				baseCalls++
				if cut == "base-refusal" {
					return nil, failure
				}
				out, err := base.Run(c, command, args...)
				if cut == "lost-ACK" {
					return nil, failure
				}
				return out, err
			}), binding: b, scoped: model.p, plan: plan, tools: runtime.Tools, guard: runtime.Guard}
			if cut == "guard" || cut == "cancel" {
				runner.guard = func(context.Context, int) error {
					if cut == "cancel" {
						cancel()
						return nil
					}
					return failure
				}
			}
			runtime.Runner = runner
			custody := &nfqwsPolicyRecovery{index: -1}
			custody.self = custody
			err = applyPolicyEffectsWithOriginalRecovery(ctx, runtime, plan, root, b.options, nil, custody)
			t.Cleanup(custody.close)
			if err == nil {
				t.Fatal("failure disappeared")
			}
			beforeBase := cut == "guard" || cut == "cancel"
			if custody.retained != beforeBase || custody.entered == beforeBase || (baseCalls == 0) != beforeBase {
				t.Fatal("issued boundary changed knowledge", cut, err, custody.retained, custody.entered, baseCalls)
			}
			if beforeBase && (custody.session.doc.Steps[0].State != "intent" || len(model.calls) != 0) {
				t.Fatal("pure refusal lost original durable intent or mutated kernel")
			}
		})
	}
}

func TestNFQWSActiveIssuedBoundaryExactOuterAndCustomFallback(t *testing.T) {
	for _, kind := range []string{"original", "copied", "foreign-session", "custom-wrapper"} {
		t.Run(kind, func(t *testing.T) {
			r, fixture, ctx, _ := nfqActivePreAddFixture(t)
			custody := r.custody
			failure := errors.New("original pure command guard refused")
			r.runner.guard = func(context.Context, int) error { return failure }
			switch kind {
			case "copied":
				copy := *r
				fixture.runtime.Runner = &copy
			case "foreign-session":
				r.custody = &nfqwsPolicyRecovery{}
			case "custom-wrapper":
				fixture.runtime.Runner = policyEffectInvocationTestRunner(func(c context.Context, name string, args ...string) ([]byte, error) { return r.Run(c, name, args...) })
			}
			_, err := custody.session.runCommand(ctx, fixture.runtime, 0, false, fixture.plan.Effects[0].Add)
			custody.finishApply()
			precise := kind == "original"
			if err == nil || custody.entered == precise || custody.retained != precise || len(fixture.calls) != 0 {
				t.Fatal("outer provenance/conservative fallback changed", kind, err, custody.entered, custody.retained, fixture.calls)
			}
			// Fixture retained its writer before this test invoked a command;
			// finishApply's ordinary non-retained path would close it in Apply.
			if !custody.retained {
				custody.session.borrow.close()
				custody.session.close()
			}
		})
	}
}

func TestNFQWSIssuedInvocationRejectsForeignKnowledge(t *testing.T) {
	for _, cut := range []string{"positive", "copy", "context", "derived-context", "canceled", "closed", "used", "cleanup", "recovery", "session", "index", "borrow", "tools", "args", "root", "plan", "already-entered"} {
		t.Run(cut, func(t *testing.T) {
			r, fixture, ctx, _ := nfqActivePreAddFixture(t)
			c := r.custody
			i := &policyEffectCommandInvocation{session: c.session, tools: fixture.runtime.Tools, index: 0, open: true, nfqRecovery: c}
			i.self = i
			ctx = context.WithValue(ctx, policyEffectCommandInvocationKey{}, i)
			i.nfqContext = ctx
			args := append([]string(nil), fixture.plan.Effects[0].Add...)
			command := fixture.runtime.Tools.command(fixture.plan.Effects[0].Tool)
			switch cut {
			case "copy":
				i = &policyEffectCommandInvocation{self: i, session: i.session, tools: i.tools, index: i.index, open: true, nfqRecovery: c, nfqContext: ctx}
			case "context":
				ctx = context.WithValue(ctx, policyEffectCommandInvocationKey{}, &policyEffectCommandInvocation{})
			case "derived-context":
				ctx = context.WithValue(ctx, struct{ derived bool }{true}, true)
			case "canceled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "closed":
				i.open = false
			case "used":
				i.used = true
			case "cleanup":
				i.cleanup = true
			case "recovery":
				i.nfqRecovery = &nfqwsPolicyRecovery{}
			case "session":
				i.session = &policyEffectSession{}
			case "index":
				i.index++
			case "borrow":
				ctx = context.WithValue(ctx, policyEffectReceiptBorrowKey{}, &policyEffectReceiptBorrow{})
			case "tools":
				i.tools.IPTables += "-foreign"
			case "args":
				args = append(args, "foreign")
			case "root":
				c.session.path += "-foreign"
			case "plan":
				r.runner.plan.Generation += "-foreign"
			case "already-entered":
				c.entered = true
			}
			err := i.enterNFQWSBase(ctx, r.runner, 0, command, args)
			if cut == "positive" {
				if err != nil || !c.entered || i.used {
					t.Fatal("precise marker consumed Start or failed", err)
				}
				if err := i.enterNFQWSBase(ctx, r.runner, 0, command, args); err == nil {
					t.Fatal("entry repeated")
				}
			} else if err == nil || (cut != "already-entered" && c.entered) {
				t.Fatal("foreign knowledge accepted", cut, err, c.entered)
			}
		})
	}
}

func TestNFQWSIssuedBoundaryCleanupNeverChangesAddKnowledge(t *testing.T) {
	r, fixture, ctx, _ := nfqActivePreAddFixture(t)
	before := r.custody.entered
	fixture.runtime.Runner = policyEffectInvocationTestRunner(func(context.Context, string, ...string) ([]byte, error) {
		return nil, errors.New("cleanup test refusal")
	})
	_, _ = r.custody.session.runCommand(ctx, fixture.runtime, 0, true, fixture.plan.Effects[0].Delete)
	if r.custody.entered != before {
		t.Fatal("cleanup changed Add knowledge")
	}
}
