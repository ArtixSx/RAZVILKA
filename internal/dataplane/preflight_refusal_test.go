package dataplane

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

type preflightRuntimeAdapter struct {
	*networkExecutionAdapter
	runtime string
}

func (a *preflightRuntimeAdapter) Rollback(ctx context.Context, plan Plan, root string) error {
	if err := a.fakeAdapter.Rollback(ctx, plan, root); err != nil {
		return err
	}
	return os.WriteFile(a.runtime, []byte("working-before"), 0o600)
}

func TestPreflightRefusalAfterEarlierLiveMutationStillRestoresRuntime(t *testing.T) {
	for _, phase := range []string{"second-activate", "health"} {
		t.Run(phase, func(t *testing.T) {
			root := t.TempDir()
			runtime := filepath.Join(root, "runtime")
			if err := os.WriteFile(runtime, []byte("working-before"), 0o600); err != nil {
				t.Fatal(err)
			}
			manager := New(filepath.Join(root, "manager"))
			manager.FreshProfile = func(context.Context) (string, error) { return executionNetwork, nil }
			refused := errors.New("required capability is unavailable")
			first := &preflightRuntimeAdapter{runtime: runtime, networkExecutionAdapter: &networkExecutionAdapter{fakeAdapter: &fakeAdapter{id: "sing-box"}, after: func(current string) error {
				if current == "activate" {
					return os.WriteFile(runtime, []byte("candidate-live"), 0o600)
				}
				if phase == "health" && current == "health" {
					return preflightRefusalError{refused}
				}
				return nil
			}}}
			second := &networkExecutionAdapter{fakeAdapter: &fakeAdapter{id: "xray"}, after: func(current string) error {
				if phase == "second-activate" && current == "activate" {
					return preflightRefusalError{refused}
				}
				return nil
			}}
			for _, adapter := range []Adapter{first, second} {
				if err := manager.Register(adapter); err != nil {
					t.Fatal(err)
				}
			}
			plan := networkExecutionPlan()
			plan.Adapters = append(plan.Adapters, "xray")
			execution, err := manager.Apply(context.Background(), plan, nil)
			data, readErr := os.ReadFile(runtime)
			if !errors.Is(err, refused) || execution.State != "rolled-back" || !first.rollback || !second.rollback || readErr != nil || string(data) != "working-before" {
				t.Fatalf("later preflight refusal skipped rollback: state=%s first=%v second=%v runtime=%s err=%v read=%v", execution.State, first.calls, second.calls, data, err, readErr)
			}
		})
	}
}
