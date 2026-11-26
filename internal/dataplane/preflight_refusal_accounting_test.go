package dataplane

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"testing"
)

func accountingRefusal(t *testing.T, phase string, cause error) (Execution, error, *networkExecutionAdapter) {
	t.Helper()
	m := New(t.TempDir())
	m.FreshProfile = func(context.Context) (string, error) { return executionNetwork, nil }
	a := &networkExecutionAdapter{fakeAdapter: &fakeAdapter{id: "sing-box"}, after: func(current string) error {
		if current == phase {
			return cause
		}
		return nil
	}}
	if err := m.Register(a); err != nil {
		t.Fatal(err)
	}
	x, err := m.Apply(context.Background(), networkExecutionPlan(), nil)
	return x, err, a
}

func TestConfirmedPreEffectRefusalUsesOriginalManagerReadOnlyFailure(t *testing.T) {
	for _, phase := range []string{"snapshot", "stage", "validate"} {
		t.Run(phase, func(t *testing.T) {
			x, err, adapter := accountingRefusal(t, phase, preflightRefusalError{errors.New("read-only refusal")})
			if !ConfirmedPreEffectRefusal(x, fmt.Errorf("caller: %w", err)) || slices.Contains(adapter.calls, "activate") || adapter.rollback {
				t.Fatalf("original pre-effect refusal was not recognized: %+v %v %v", x, err, adapter.calls)
			}
			for name, cause := range map[string]error{
				"unknown-close": errors.Join(err, errors.New("unknown native close outcome")),
				"journal":       errors.Join(err, executionJournalError(errors.New("unknown durable outcome"))),
			} {
				if ConfirmedPreEffectRefusal(x, cause) {
					t.Fatal("a read-only rejection hid a later uncertain failure", name)
				}
			}
			// Journal labels without the original private marker are not proof.
			if ConfirmedPreEffectRefusal(x, errors.New("lookalike refusal")) {
				t.Fatal("untyped error received a refund")
			}
			for _, mutate := range []func(*Execution){
				func(x *Execution) { x.Resources = []ExecutionResource{{State: "unused"}} },
				func(x *Execution) { x.ResourcePlanID = "temporary-resource" },
				func(x *Execution) { x.Steps = append(x.Steps, ExecutionStep{Phase: "activate", State: "failed"}) },
			} {
				copy := x
				copy.Steps = slices.Clone(x.Steps)
				mutate(&copy)
				if ConfirmedPreEffectRefusal(copy, err) {
					t.Fatal("resources or possible effects received a refund")
				}
			}
		})
	}
}

func TestConfirmedPreEffectRefusalRejectsUnknownAndPostEffectFailures(t *testing.T) {
	for _, phase := range []string{"snapshot", "stage", "validate", "canary", "activate", "health", "commit-adapter"} {
		for _, typed := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/typed=%t", phase, typed), func(t *testing.T) {
				cause := error(errors.New("unknown phase failure"))
				if typed {
					cause = preflightRefusalError{cause}
				}
				x, err, _ := accountingRefusal(t, phase, cause)
				want := typed && (phase == "snapshot" || phase == "stage" || phase == "validate")
				if got := ConfirmedPreEffectRefusal(x, err); got != want {
					t.Fatalf("unknown/post-effect classification=%t want %t: %+v %v", got, want, x, err)
				}
			})
		}
	}
}
