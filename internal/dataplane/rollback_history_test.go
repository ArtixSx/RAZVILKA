package dataplane

import (
	"context"
	"path/filepath"
	"testing"
)

// G02-T01: many failed recovery attempts must not permanently exceed the
// review bound. Once the cause is fixed, an ordinary retry succeeds; the
// original transaction record stays intact and the history stays bounded.
func TestRollbackRetryHistoryStaysRecoverableAfterManyFailures(t *testing.T) {
	m, adapter, p, original := rollbackRetryFixture(t)
	guard := func(Plan) error { return nil }
	adapter.failAt = "rollback"
	for attempt := 0; attempt < 60; attempt++ {
		if _, err := m.RetryFailedRollback(context.Background(), p.PlanID, p.Digest, guard); err == nil {
			t.Fatalf("attempt %d succeeded while rollback still fails", attempt)
		}
		var latest *Execution
		if _, err := readOptionalJournal(filepath.Join(m.StateRoot, "latest-execution.json"), &latest); err != nil || latest == nil {
			t.Fatal(err)
		}
		if len(latest.Steps) > maxRecoveryJournalSteps || len(latest.Error) > maxRecoveryJournalError {
			t.Fatalf("attempt %d: unbounded history: %d steps, %d bytes of error", attempt, len(latest.Steps), len(latest.Error))
		}
		for i, step := range original.Steps {
			if latest.Steps[i].Phase != step.Phase || latest.Steps[i].State != step.State {
				t.Fatalf("attempt %d rewrote the original transaction record at step %d", attempt, i)
			}
		}
	}
	adapter.failAt = ""
	result, err := m.RetryFailedRollback(context.Background(), p.PlanID, p.Digest, guard)
	if err != nil || result.State != "rolled-back" || !result.RollbackVerified {
		t.Fatalf("recovery unavailable after the cause was fixed: %+v %v", result, err)
	}
	if err := m.checkExecutionRecovery(); err != nil {
		t.Fatal("fence remained after verified recovery", err)
	}
}
