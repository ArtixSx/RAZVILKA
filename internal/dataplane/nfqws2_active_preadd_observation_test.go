package dataplane

import (
	"context"
	"errors"
	"reflect"
	"testing"
)

// Actual registrar/writer/root/image, explicit tool and kernel models. Native
// source closure and full Apply/Stop remain the separate Linux acceptance.
func nfqActivePreAddFixture(t *testing.T) (*nfqws2ActivePreAddRead, *policyEffectFixture, context.Context, *activePredicateObservationModel) {
	t.Helper()
	e, ctx, f := nfqwsActiveCommandPolicyFixture(t)
	e.material.execution, e.material.executionBound = e, true
	model := &activePredicateObservationModel{}
	e.inventory.reader.Runner = model
	e.binding.activeReadback = e
	e.binding.network = &nfqwsScopedNetworkBinding{provider: e.material.provider, inventory: e.inventory}
	c := &nfqwsPolicyRecovery{execution: e, index: -1}
	c.self = c
	e.partialRecovery = c
	cut := errors.New("retained actual original intent")
	f.options.fault = func(point string, index int) error {
		if point == "intent" && index == 0 {
			return cut
		}
		return nil
	}
	if err := applyPolicyEffectsWithOriginalRecovery(ctx, f.runtime, f.plan, f.root, f.options, nil, c); !errors.Is(err, cut) || !c.retained || c.entered {
		t.Fatal("actual original writer missing", err)
	}
	t.Cleanup(c.close)
	f.options.fault, c.session.options.fault = nil, nil
	f.runtime.Runner = nfqwsScopedApplyRunner{base: f, binding: e.binding, scoped: e.resource.Plan(), plan: f.plan, tools: f.runtime.Tools, guard: f.runtime.Guard}
	var err error
	f.runtime, err = newNFQWSActivePreAddRead(e, e.binding, e.resource.Plan(), f.runtime, f.plan, f.root, c)
	if err != nil {
		t.Fatal(err)
	}
	return c.preAdd, f, context.WithValue(ctx, policyEffectReceiptBorrowKey{}, c.session.borrow), model
}

func TestNFQWSActivePreAddSharesBytesPreservesFourFreshCallsAndRunBoundary(t *testing.T) {
	r, f, ctx, model := nfqActivePreAddFixture(t)
	var order []string
	var escaped context.Context
	f.runtime.ExactPresence = func(c context.Context, index int) (int, error) {
		if c.Value(nfqws2ActivePreAddKey{}) != r || c.Value(activePredicateObservationKey{}) != model || index != 0 {
			t.Fatal("read escaped original scope/index")
		}
		escaped = c
		order = append(order, "presence")
		if _, err := r.Run(c, f.runtime.Tools.IPTables, f.plan.Effects[0].Add...); err == nil || len(f.calls) != 0 {
			t.Fatal("read scope issued an effect")
		}
		return 0, nil
	}
	f.runtime.Guard = func(c context.Context, index int) error {
		if c.Value(nfqws2ActivePreAddKey{}) != r || index != 0 {
			t.Fatal("guard escaped original scope/index")
		}
		order = append(order, "guard")
		return nil
	}
	if err := r.custody.session.observeBeforeAdd(ctx, f.runtime, 0); err != nil || model.called != 1 || !reflect.DeepEqual(order, []string{"presence", "guard", "presence", "guard"}) {
		t.Fatal("four fresh reads were replaced/reordered", err, model.called, order)
	}
	if r.custody.entered || len(f.calls) != 0 || r.custody.session.doc.Steps[0].State != "intent" {
		t.Fatal("read loan changed durable/command knowledge")
	}
	if _, err := r.Run(escaped, "unused"); err == nil {
		t.Fatal("escaped context reached runner")
	}
	// Model the existing private Apply runner's first Guard; the source read
	// scope has closed before any real command preparation can begin.
	stop := errors.New("unborrowed original runner reached")
	r.runner.guard = func(c context.Context, _ int) error {
		if c.Value(nfqws2ActivePreAddKey{}) != nil || c.Value(activePredicateObservationKey{}) != nil {
			t.Fatal("actual command inherited a borrowed context")
		}
		return stop
	}
	if _, err := r.Run(ctx, f.runtime.Tools.command(f.plan.Effects[0].Tool), f.plan.Effects[0].Add...); !errors.Is(err, stop) {
		t.Fatal("ordinary original command path changed", err)
	}
}

func TestNFQWSActivePreAddClosingFailureNeverReachesCommand(t *testing.T) {
	for _, cut := range []string{"source", "owner", "cancel", "last-guard", "receipt"} {
		t.Run(cut, func(t *testing.T) {
			r, f, ctx, model := nfqActivePreAddFixture(t)
			ctx, cancel := context.WithCancel(ctx)
			defer cancel()
			failure := errors.New("last original read refused")
			guards, presence := 0, 0
			f.runtime.ExactPresence = func(context.Context, int) (int, error) { presence++; return 0, nil }
			f.runtime.Guard = func(context.Context, int) error {
				guards++
				if guards == 2 {
					switch cut {
					case "source":
						model.closing = failure
					case "owner":
						r.execution.binding = &NFQWSScopedBinding{}
					case "cancel":
						cancel()
					case "last-guard":
						return failure
					case "receipt":
						r.custody.session.doc.Checksum = "changed"
					}
				}
				return nil
			}
			err := r.custody.session.observeBeforeAdd(ctx, f.runtime, 0)
			if err == nil || guards != 2 || presence != 2 || model.called != 1 || r.custody.entered || len(f.calls) != 0 || r.custody.session.doc.Steps[0].State != "intent" {
				t.Fatal("closing failure lost its fence", err, guards, presence, model.called)
			}
			if (cut == "source" || cut == "last-guard") && !errors.Is(err, failure) || cut == "cancel" && !errors.Is(err, context.Canceled) {
				t.Fatal("original failure cause lost", err)
			}
		})
	}
}

func TestNFQWSActivePreAddRejectsCopiedOrForeignOriginalCustody(t *testing.T) {
	for _, cut := range []string{"copy", "root", "runner", "index", "session", "entered", "borrow", "nested"} {
		t.Run(cut, func(t *testing.T) {
			r, f, ctx, model := nfqActivePreAddFixture(t)
			s, index := r.custody.session, 0
			switch cut {
			case "copy":
				copied := *r
				r = &copied
			case "root":
				r.root += "/foreign"
			case "runner":
				f.runtime.Runner = f
			case "index":
				index = 1
			case "session":
				copied := *s
				s = &copied
			case "entered":
				r.custody.entered = true
			case "borrow":
				ctx = context.WithValue(ctx, policyEffectReceiptBorrowKey{}, &policyEffectReceiptBorrow{})
			case "nested":
				ctx = context.WithValue(ctx, nfqws2ActivePreAddKey{}, r)
			}
			if err := r.observe(ctx, s, f.runtime, index); err == nil || model.called != 0 || len(f.calls) != 0 {
				t.Fatal("foreign/copied owner acquired read scope", err, model.called)
			}
		})
	}
}

func TestNFQWSPreAddGenericAndProbeFallbackKeepOriginalRuntime(t *testing.T) {
	for _, mode := range []string{"generic", "probe-binding"} {
		t.Run(mode, func(t *testing.T) {
			f := newPolicyEffectFixture(t)
			guard, presence := f.runtime.Guard, f.runtime.ExactPresence
			f.runtime.Guard = func(c context.Context, index int) error {
				if c.Value(nfqws2ActivePreAddKey{}) != nil {
					t.Fatal("nonoriginal guard acquired a loan")
				}
				return guard(c, index)
			}
			f.runtime.ExactPresence = func(c context.Context, index int) (int, error) {
				if c.Value(nfqws2ActivePreAddKey{}) != nil {
					t.Fatal("nonoriginal presence acquired a loan")
				}
				return presence(c, index)
			}
			var err error
			if mode == "generic" {
				err = f.apply()
			} else {
				// A probe/custom binding has no private activeReadback issuer.
				b := &NFQWSScopedBinding{options: f.options}
				err = b.applyOriginalPolicyEffects(context.Background(), nil, f.runtime, f.plan, f.root)
			}
			if err != nil || len(f.calls) != len(f.plan.Effects) {
				t.Fatal("original fallback changed", err, len(f.calls))
			}
		})
	}
}
