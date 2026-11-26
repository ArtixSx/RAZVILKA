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
	for _, mode := range []string{"pass", "digest", "different-plan", "guard", "missing-journal", "mismatch", "config-commit", "unconfirmed", "retry-failed", "interrupted-retry", "canceled", "foreign-adapter"} {
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
			case "foreign-adapter":
				// Same adapter count, different adapter: the journal must not
				// authorize rolling back a runtime the plan never owned.
				previous, _, _ := m.Committed()
				previous.Adapters, p.Adapters = []string{"nfqws2"}, []string{"nfqws2"}
				if err := m.Record(previous); err != nil {
					t.Fatal(err)
				}
				if err := m.Record(p); err != nil {
					t.Fatal(err)
				}
			}
			result, err := m.RetryFailedRollback(ctx, id, digest, guard)
			if mode == "pass" || mode == "interrupted-retry" || mode == "unconfirmed" {
				// An exact restoration without a live receipt closes the journal
				// as Apply does, unverified.
				if err != nil || result.State != "rolled-back" || result.RollbackVerified != (mode != "unconfirmed") || !adapter.rollback {
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
				if mode != "retry-failed" && len(adapter.calls) > 0 {
					t.Fatal("mutation before guard", adapter.calls)
				}
				if err := m.checkExecutionRecovery(); err == nil {
					t.Fatal("fence erased")
				}
			}
		})
	}
}

// Startup retries the latest failed rollback without a person: an exact
// restoration closes the journal, anything else keeps the fence.
func TestRetryLatestFailedRollbackAtStartup(t *testing.T) {
	clean := New(t.TempDir())
	if _, attempted, err := clean.RetryLatestFailedRollback(context.Background(), func(Plan) error { return nil }); attempted || err != nil {
		t.Fatal("retried without a failed rollback", attempted, err)
	}
	for _, mode := range []string{"pass", "mismatch"} {
		t.Run(mode, func(t *testing.T) {
			m, adapter, p, _ := rollbackRetryFixture(t)
			if mode == "mismatch" {
				adapter.verify = func(context.Context) (bool, error) {
					return false, errors.New("restored proxy processes differ from snapshot")
				}
			}
			result, attempted, err := m.RetryLatestFailedRollback(context.Background(), func(Plan) error { return nil })
			if !attempted || result.PlanID != p.PlanID {
				t.Fatal("failed rollback not retried", attempted, result.PlanID)
			}
			if mode == "pass" && (err != nil || result.State != "rolled-back" || m.checkExecutionRecovery() != nil) {
				t.Fatal("exact restoration did not close the journal", result, err)
			}
			if mode == "mismatch" && (err == nil || m.checkExecutionRecovery() == nil) {
				t.Fatal("mismatch closed the journal", result, err)
			}
		})
	}
}
