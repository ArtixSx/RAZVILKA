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
