package dataplane

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
)

func TestCloseFailedRollbackDeactivatesBeforeClearingTheFence(t *testing.T) {
	for _, mode := range []string{"pass", "digest", "guard", "deactivate-failed-then-pass"} {
		t.Run(mode, func(t *testing.T) {
			m, adapter, p, _ := rollbackRetryFixture(t)
			// After a reboot the recorded runtime cannot be matched again.
			adapter.verify = func(context.Context) (bool, error) {
				return false, errors.New("restored proxy processes differ from snapshot")
			}
			if _, err := m.RetryFailedRollback(context.Background(), p.PlanID, p.Digest, func(Plan) error { return nil }); err == nil {
				t.Fatal("fixture did not reproduce an unretryable rollback")
			}
			adapter.calls, adapter.deactivated = nil, false
			id, digest := p.PlanID, p.Digest
			guard := func(previous Plan) error {
				if previous.PlanID != "dp-1111111111111111" {
					t.Fatal(previous)
				}
				return nil
			}
			switch mode {
			case "digest":
				digest = strings.Repeat("a", 64)
			case "guard":
				guard = func(Plan) error { return errors.New("settings changed") }
			case "deactivate-failed-then-pass":
				adapter.failAt = "deactivate"
			}
			result, err := m.CloseFailedRollback(context.Background(), id, digest, guard)
			switch mode {
			case "pass":
			case "deactivate-failed-then-pass":
				if err == nil || result.State != "rollback-failed" || m.checkExecutionRecovery() == nil {
					t.Fatal("failed deactivation cleared the fence", result, err)
				}
				adapter.failAt = ""
				result, err = m.CloseFailedRollback(context.Background(), id, digest, guard)
			default:
				if err == nil || adapter.deactivated || len(adapter.calls) != 0 || m.checkExecutionRecovery() == nil {
					t.Fatal("refused close changed state", mode, err, adapter.calls)
				}
				return
			}
			if err != nil || result.State != "rolled-back" || result.RollbackVerified || !adapter.deactivated || !strings.Contains(result.Error, "not verified") {
				t.Fatal(result, err)
			}
			if !slices.ContainsFunc(result.Steps, func(s ExecutionStep) bool { return s.Phase == "close-deactivate" && s.State == "passed" }) {
				t.Fatal("close step not journaled", result.Steps)
			}
			if err := m.checkExecutionRecovery(); err != nil {
				t.Fatal("fence remains after a verified close", err)
			}
			if previous, _, _ := m.Committed(); previous.PlanID != "dp-1111111111111111" {
				t.Fatal("close overwrote committed intent")
			}
			if latest, _, _ := m.Latest(); latest.State != "rolled-back" || !strings.Contains(latest.Note, "closed") {
				t.Fatal("plan not closed", latest.State, latest.Note)
			}
		})
	}
}
