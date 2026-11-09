package dataplane

import (
	"context"
	"errors"
	"testing"
)

type activeRPDBModel struct {
	calls   int
	closing error
	mode    string
	before  func()
}

func (*activeRPDBModel) Run(context.Context, string, ...string) ([]byte, error) {
	return nil, ErrNFQWSScopedOwner
}
func (m *activeRPDBModel) WithOriginalNFQWSLANRPDB(c context.Context, use func(context.Context) error) error {
	m.calls++
	if m.before != nil {
		m.before()
	}
	if m.mode == "zero" {
		return nil
	}
	err := use(c)
	if m.mode == "double" {
		_ = use(c)
	}
	if m.mode == "swallow" || m.mode == "double" {
		return nil
	}
	return errors.Join(err, m.closing)
}
func TestNFQWSActiveRPDBOriginalSourceAndClosing(t *testing.T) {
	for _, kind := range []string{"original", "foreign-runner", "closing-runner", "closing-source", "closing-plan", "closing-error", "callback-error"} {
		t.Run(kind, func(t *testing.T) {
			e, c := nfqwsActiveCommandFixture(t)
			e.material.execution, e.material.executionBound = e, true
			m := &activeRPDBModel{}
			e.runtime.Runner = m
			e.runtimeFrozen.Runner = m
			e.binding.Runner = m
			lan := &LANPolicyRuntimePlan{Mode: LANPolicyNFQWSDirectMode}
			e.plan.LAN = lan
			sentinel := errors.New("original read refused")
			if kind == "foreign-runner" {
				e.runtime.Runner = &activeRPDBModel{}
			}
			if kind == "closing-error" {
				m.closing = sentinel
			}
			called := false
			err := e.verifyLANRPDB(c, lan, func(context.Context) error {
				called = true
				switch kind {
				case "closing-runner":
					e.runtime.Runner = &activeRPDBModel{}
				case "closing-source":
					e.material.execution = nil
				case "closing-plan":
					lan.Generation = "changed-original-intent"
				case "callback-error":
					return sentinel
				}
				return nil
			})
			if kind == "original" {
				if err != nil || !called || m.calls != 1 {
					t.Fatal(err, called, m.calls)
				}
				return
			}
			if err == nil {
				t.Fatal("original source change accepted", kind)
			}
			if kind == "foreign-runner" && (called || m.calls != 0) {
				t.Fatal("foreign runner dispatched")
			}
			if (kind == "closing-error" || kind == "callback-error") && !errors.Is(err, sentinel) {
				t.Fatal("cause lost", err)
			}
		})
	}
}

func TestNFQWSActiveRPDBCustomIssuerCannotSkipOrHideVerify(t *testing.T) {
	for _, mode := range []string{"zero", "double", "swallow", "before-mutation"} {
		t.Run(mode, func(t *testing.T) {
			e, c := nfqwsActiveCommandFixture(t)
			e.material.execution, e.material.executionBound = e, true
			m := &activeRPDBModel{mode: mode}
			e.runtime.Runner = m
			e.runtimeFrozen.Runner = m
			e.binding.Runner = m
			lan := &LANPolicyRuntimePlan{Mode: LANPolicyNFQWSDirectMode}
			e.plan.LAN = lan
			if mode == "before-mutation" {
				m.before = func() { e.material.execution = nil }
			}
			sentinel := errors.New("actual Verify refused")
			calls := 0
			err := e.verifyLANRPDB(c, lan, func(context.Context) error {
				calls++
				if mode == "swallow" {
					return sentinel
				}
				return nil
			})
			if err == nil {
				t.Fatal("custom issuer bypassed Verify", mode)
			}
			want := 1
			if mode == "zero" || mode == "before-mutation" {
				want = 0
			}
			if calls != want {
				t.Fatal("unexpected Verify calls", calls, want)
			}
			if mode == "swallow" && !errors.Is(err, sentinel) {
				t.Fatal("swallowed Verify error", err)
			}
		})
	}
}
