package dataplane

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func rollbackRetryFixture(t *testing.T) (*Manager, *rollbackVerifierFake, Plan, Execution) {
	t.Helper()
	m := New(t.TempDir())
	base := &networkExecutionAdapter{fakeAdapter: &fakeAdapter{id: "sing-box"}}
	adapter := &rollbackVerifierFake{networkExecutionAdapter: base, verify: func(context.Context) (bool, error) { return true, nil }}
	if err := m.Register(adapter); err != nil {
		t.Fatal(err)
	}
	previous := networkExecutionPlan()
	previous.PlanID = "dp-1111111111111111"
	previous.Digest = strings.Repeat("1", 64)
	previous.State = "committed"
	if err := m.Record(previous); err != nil {
		t.Fatal(err)
	}
	plan := previous
	plan.PlanID = "dp-2222222222222222"
	plan.Digest = strings.Repeat("2", 64)
	plan.State = "rollback-failed"
	plan.Ready = false
	if err := m.Record(plan); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	e := Execution{PlanID: plan.PlanID, Digest: plan.Digest, State: "rollback-failed", StartedAt: now, FinishedAt: now}
	for _, phase := range []string{"snapshot", "stage", "validate", "activate", "health", "commit-adapter", "rollback", "verify-rollback"} {
		state := "passed"
		if phase == "commit-adapter" || phase == "rollback" || phase == "verify-rollback" {
			state = "failed"
		}
		e.Steps = append(e.Steps, ExecutionStep{Adapter: "sing-box", Phase: phase, State: state, StartedAt: now, FinishedAt: now})
	}
	root := filepath.Join(m.StateRoot, "transactions", plan.PlanID)
	if err := m.prepareExecutionRoot(root); err != nil {
		t.Fatal(err)
	}
	if err := m.writeExecution(root, e); err != nil {
		t.Fatal(err)
	}
	return m, adapter, plan, e
}

func TestRollbackRetryRequiresExactPreCommitFailureAndMatchingSettings(t *testing.T) {
	for _, mode := range []string{"pass", "digest", "different-plan", "guard", "missing-journal", "mismatch", "config-commit", "unconfirmed", "retry-failed", "interrupted-retry", "canceled"} {
		t.Run(mode, func(t *testing.T) {
			m, adapter, p, e := rollbackRetryFixture(t)
			root := filepath.Join(m.StateRoot, "transactions", p.PlanID)
			guard := func(previous Plan) error {
				if previous.PlanID != "dp-1111111111111111" {
					t.Fatal(previous)
				}
				return nil
			}
			id, digest := p.PlanID, p.Digest
			ctx := context.Background()
			switch mode {
			case "digest":
				digest = strings.Repeat("a", 64)
			case "different-plan":
				id = "dp-3333333333333333"
			case "guard":
				guard = func(Plan) error { return errors.New("settings changed") }
			case "missing-journal":
				if err := os.Remove(filepath.Join(root, "execution.json")); err != nil {
					t.Fatal(err)
				}
			case "mismatch":
				e.Error = "different"
				data, _ := json.Marshal(e)
				if err := os.WriteFile(filepath.Join(root, "execution.json"), data, 0600); err != nil {
					t.Fatal(err)
				}
			case "config-commit":
				e.Steps[5].State = "passed"
				if err := m.writeExecution(root, e); err != nil {
					t.Fatal(err)
				}
			case "unconfirmed":
				adapter.verify = func(context.Context) (bool, error) { return false, nil }
			case "retry-failed":
				adapter.failAt = "rollback"
			case "interrupted-retry":
				e.Steps = append(e.Steps, ExecutionStep{Adapter: "sing-box", Phase: "retry-rollback", State: "running", StartedAt: e.StartedAt})
				if err := m.writeExecution(root, e); err != nil {
					t.Fatal(err)
				}
			case "canceled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			result, err := m.RetryFailedRollback(ctx, id, digest, guard)
			if mode == "pass" || mode == "interrupted-retry" {
				if err != nil || result.State != "rolled-back" || !result.RollbackVerified || !adapter.rollback {
					t.Fatal(result, err)
				}
				if err := m.checkExecutionRecovery(); err != nil {
					t.Fatal("fence still active", err)
				}
				previous, _, _ := m.Committed()
				if previous.PlanID != "dp-1111111111111111" {
					t.Fatal("overwrote committed intent")
				}
			} else {
				if err == nil {
					t.Fatal("unsafe success", result)
				}
				if mode != "unconfirmed" && mode != "retry-failed" && len(adapter.calls) > 0 {
					t.Fatal("mutation before guard", adapter.calls)
				}
				if err := m.checkExecutionRecovery(); err == nil {
					t.Fatal("fence erased")
				}
			}
		})
	}
}
