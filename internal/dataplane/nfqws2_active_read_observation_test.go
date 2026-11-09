package dataplane

import (
	"context"
	"errors"
	"github.com/ArtixSx/razvilka/internal/netidentity"
	"testing"
)

// Dispatch/identity model around the actual Manager fixture. This runner does
// not issue a real held-tool loan or claim native byte/kernel verification.
// Existing native tool fixtures exercise revocation, mutation and sole Wait.
type activeReadDispatchModel struct{ called int }

func (*activeReadDispatchModel) Run(context.Context, string, ...string) ([]byte, error) {
	return nil, ErrNFQWSScopedOwner
}
func (m *activeReadDispatchModel) WithReadOnlyToolObservation(c context.Context, _ netidentity.Identity, _ string, f func(context.Context) error) error {
	m.called++
	return f(c)
}
func TestNFQWSActiveReadObservationOriginalDispatchAndClosingIdentity(t *testing.T) {
	for _, kind := range []string{"original", "copy", "malformed", "canceled", "foreign-plan", "changed-source", "closing-owner", "callback-error"} {
		t.Run(kind, func(t *testing.T) {
			e, c := nfqwsActiveCommandFixture(t)
			e.material.execution, e.material.executionBound = e, true
			model := &activeReadDispatchModel{}
			e.inventory.reader.Runner = model
			p := e.resource.Plan()
			switch kind {
			case "copy":
				copy := &nfqws2ActiveExecution{self: e, material: e.material, binding: e.binding, resource: e.resource}
				c = context.WithValue(c, nfqws2ActiveExecutionKey{}, copy)
			case "malformed":
				c = context.WithValue(c, nfqws2ActiveExecutionKey{}, true)
			case "canceled":
				var cancel context.CancelFunc
				c, cancel = context.WithCancel(c)
				cancel()
			case "foreign-plan":
				p = &NFQWSScopedPlan{}
			case "changed-source":
				e.material.execution = &nfqws2ActiveExecution{}
			}
			sentinel := errors.New("original callback refusal")
			entered := false
			err := e.binding.observeProbeTools(c, p, func(context.Context) error {
				entered = true
				if kind == "closing-owner" {
					e.material.adapter.activeExecution = nil
				}
				if kind == "callback-error" {
					return sentinel
				}
				return nil
			})
			if kind == "original" {
				if err != nil || !entered || model.called != 1 {
					t.Fatal("original dispatch", err, entered, model.called)
				}
				return
			}
			if err == nil {
				t.Fatal("invalid owner escaped", kind)
			}
			if kind == "callback-error" {
				if !errors.Is(err, sentinel) {
					t.Fatal("cause lost", err)
				}
				return
			}
			if kind != "closing-owner" && (entered || model.called != 0) {
				t.Fatal("invalid dispatch reached loan")
			}
		})
	}
}
func TestNFQWSActiveReadObservationPreservesReadonlyCopyAndBareFallback(t *testing.T) {
	e, c := nfqwsActiveCommandFixture(t)
	model := &activeReadDispatchModel{}
	e.inventory.reader.Runner = model
	copy := *e.binding
	count := 0
	callback := func(got context.Context) error {
		count++
		if got != c {
			t.Fatal("fallback context changed")
		}
		return nil
	}
	if err := copy.observeProbeTools(c, e.resource.Plan(), callback); err != nil || count != 1 || model.called != 0 {
		t.Fatal("readonly fallback changed", err)
	}
	bare := context.Background()
	if err := e.binding.observeProbeTools(bare, e.resource.Plan(), func(got context.Context) error {
		if got != bare {
			t.Fatal("bare context changed")
		}
		return nil
	}); err != nil || model.called != 0 {
		t.Fatal("bare fallback changed", err)
	}
}

// The model only proves dispatch at the original/copy boundary. Native tests
// separately require actual file, process, kernel and mutation observations.
type registrarReadMarker struct{}
type registrarReadDispatchModel struct {
	called  int
	closing error
}

func (*registrarReadDispatchModel) Run(context.Context, string, ...string) ([]byte, error) {
	return nil, ErrNFQWSScopedOwner
}
func (m *registrarReadDispatchModel) WithReadOnlyToolObservation(c context.Context, _ netidentity.Identity, _ string, f func(context.Context) error) error {
	m.called++
	return errors.Join(f(context.WithValue(c, registrarReadMarker{}, m)), m.closing)
}
func TestNFQWSActiveReadObservationRegistrarCopiesKeepOriginalLoan(t *testing.T) {
	for _, prepared := range []bool{false, true} {
		t.Run(map[bool]string{false: "before-start", true: "prepared"}[prepared], func(t *testing.T) {
			e, c := nfqwsActiveCommandFixture(t)
			binding, scoped, _ := nfqwsScopedBindingFixture(t)
			// Explicit model plan/binding: the first original guard refuses,
			// so no modeled kernel or process success is consumed.
			e.binding, e.resource.plan = binding, scoped.p
			e.material.execution, e.material.executionBound = e, true
			closing := errors.New("original observation closing refusal")
			model := &registrarReadDispatchModel{closing: closing}
			e.inventory.reader.Runner = model
			sentinel := errors.New("original current refusal")
			calls := 0
			current := func(got context.Context, p *NFQWSScopedPlan) error {
				calls++
				if got.Value(registrarReadMarker{}) != model || p != e.resource.Plan() {
					t.Fatal("readonly registrar lost original observation")
				}
				return sentinel
			}
			var err error
			if prepared {
				err = nfqwsScopedPreparedCurrent(c, e.binding, e.resource.Plan(), e.resource.Root(), current)
			} else {
				err = nfqwsScopedBeforeStartCurrent(c, e.binding, e.resource.Plan(), current)
			}
			if model.called != 1 || calls != 1 || !errors.Is(err, sentinel) || !errors.Is(err, closing) {
				t.Fatal("original read/closing failure not preserved", model.called, calls, err)
			}
		})
	}
}

// These production entry points previously performed their surrounding owner
// checks outside any original tool observation. An opening or closing source
// refusal must reach their caller; none may accept an intermediate observation
// or continue to a mutation after the read scope has failed.
type activePredicateObservationKey struct{}

type activePredicateObservationModel struct {
	opening, closing error
	called           int
}

func (*activePredicateObservationModel) Run(context.Context, string, ...string) ([]byte, error) {
	return nil, ErrNFQWSScopedOwner
}
func (m *activePredicateObservationModel) WithReadOnlyToolObservation(c context.Context, _ netidentity.Identity, _ string, use func(context.Context) error) error {
	if c.Value(activePredicateObservationKey{}) == m {
		return use(c) // Model the same original finite loan, not a new source.
	}
	m.called++
	if m.opening != nil {
		return m.opening
	}
	return errors.Join(use(context.WithValue(c, activePredicateObservationKey{}, m)), m.closing)
}

func TestNFQWSActivePurePredicatesPreserveToolSourceFailure(t *testing.T) {
	for _, predicate := range []string{"current", "health", "queue"} {
		for _, boundary := range []string{"opening", "closing"} {
			t.Run(predicate+"/"+boundary, func(t *testing.T) {
				e, c := nfqwsActiveCommandFixture(t)
				e.material.execution, e.material.executionBound = e, true
				failure := errors.New("original tool source changed")
				model := &activePredicateObservationModel{}
				if boundary == "opening" {
					model.opening = failure
				} else {
					model.closing = failure
				}
				e.inventory.reader.Runner = model
				// This fixture intentionally has no actual App/source admission.
				// The callback therefore refuses too; its error must not hide the
				// independently failing original tool closing observation.
				phase := e.resource.scope.execution.Resources[0].Phase
				original := e.material.adapter.activeProcess
				var err error
				switch predicate {
				case "current":
					err = e.current(c, e.resource.Plan())
				case "health":
					err = e.health(c)
				case "queue":
					var ready bool
					ready, err = e.observeOriginalQueue(c, nil)
					if ready {
						t.Fatal("failed source published queue readiness")
					}
				}
				if model.called != 1 || !errors.Is(err, failure) {
					t.Fatal("original source refusal was lost", model.called, err)
				}
				if e.resource.scope.execution.Resources[0].Phase != phase || e.material.adapter.activeProcess != original || e.retired {
					t.Fatal("read failure changed original process or journal ownership")
				}
			})
		}
	}
}
