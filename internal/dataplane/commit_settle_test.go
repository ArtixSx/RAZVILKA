package dataplane

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// committedFixture applies one plan and returns its manager, adapter and the
// final execution record written by finishCommit.
func committedFixture(t *testing.T) (*Manager, *fakeAdapter, Execution) {
	t.Helper()
	m := New(t.TempDir())
	a := &fakeAdapter{id: "sing-box"}
	if err := m.Register(a); err != nil {
		t.Fatal(err)
	}
	execution, err := m.Apply(context.Background(), journalTestPlan(), nil)
	if err != nil || execution.State != "committed" || len(execution.Steps) == 0 {
		t.Fatal(execution, err)
	}
	return m, a, execution
}

func writeJournalFile(t *testing.T, path string, value any) {
	t.Helper()
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func readExecutionFile(t *testing.T, path string) Execution {
	t.Helper()
	var execution Execution
	data, err := os.ReadFile(path)
	if err != nil || json.Unmarshal(data, &execution) != nil {
		t.Fatal(err)
	}
	return execution
}

// Power lost after the committed plan was published: only the final
// "committed" records are missing (G02-T02). The provable generation is
// completed on restart instead of fencing the router until manual repair.
func TestRecoverSettlesCommitInterruptedAfterPlanPublication(t *testing.T) {
	for name, transactionAhead := range map[string]bool{"before both records": false, "between the records": true} {
		t.Run(name, func(t *testing.T) {
			m, a, final := committedFixture(t)
			committing := final
			committing.State, committing.FinishedAt = "committing", ""
			transaction := committing
			if transactionAhead {
				transaction = final
			}
			latestPath := filepath.Join(m.StateRoot, "latest-execution.json")
			transactionPath := filepath.Join(m.StateRoot, "transactions", final.PlanID, "execution.json")
			writeJournalFile(t, latestPath, committing)
			writeJournalFile(t, transactionPath, transaction)
			restarted := New(m.StateRoot)
			if err := restarted.Register(a); err != nil {
				t.Fatal(err)
			}
			recovery, err := restarted.Recover(context.Background())
			if err != nil || recovery.State != "recovered" || len(recovery.Steps) == 0 || recovery.Steps[0].State != "settled" {
				t.Fatal(recovery, err)
			}
			latest, recorded := readExecutionFile(t, latestPath), readExecutionFile(t, transactionPath)
			if latest.State != "committed" || latest.FinishedAt == "" || latest.PlanID != final.PlanID || latest.Digest != final.Digest || latest.StartedAt != recorded.StartedAt || latest.FinishedAt != recorded.FinishedAt {
				t.Fatalf("records not completed: %+v %+v", latest, recorded)
			}
			if transactionAhead && latest.FinishedAt != final.FinishedAt {
				t.Fatal("the transaction record's own completion was not kept")
			}
		})
	}
}

// Anything that is not provable stays fenced and the evidence is unchanged.
func TestRecoverKeepsFenceForUnprovableCommitInterruptions(t *testing.T) {
	cases := map[string]func(t *testing.T, m *Manager, committing *Execution, transaction *Execution){
		"plan not published": func(t *testing.T, m *Manager, committing, transaction *Execution) {
			previous := journalTestPlan()
			previous.PlanID, previous.State = "dp-previous", "committed"
			writeJournalFile(t, filepath.Join(m.StateRoot, "latest-plan.json"), previous)
			writeJournalFile(t, filepath.Join(m.StateRoot, "latest-committed-plan.json"), previous)
		},
		"boot copy not published": func(t *testing.T, m *Manager, committing, transaction *Execution) {
			previous := journalTestPlan()
			previous.PlanID, previous.State = "dp-previous", "committed"
			writeJournalFile(t, filepath.Join(m.StateRoot, "latest-committed-plan.json"), previous)
		},
		"failed step": func(t *testing.T, m *Manager, committing, transaction *Execution) {
			committing.Steps[len(committing.Steps)-1].State = "failed"
			transaction.Steps = committing.Steps
		},
		"different executions": func(t *testing.T, m *Manager, committing, transaction *Execution) {
			transaction.Digest = "b" + transaction.Digest[1:]
		},
		"steps disagree": func(t *testing.T, m *Manager, committing, transaction *Execution) {
			transaction.Steps = transaction.Steps[:len(transaction.Steps)-1]
		},
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			m, a, final := committedFixture(t)
			committing := final
			committing.State, committing.FinishedAt = "committing", ""
			committing.Steps = append([]ExecutionStep(nil), final.Steps...)
			transaction := committing
			transaction.Steps = append([]ExecutionStep(nil), final.Steps...)
			change(t, m, &committing, &transaction)
			latestPath := filepath.Join(m.StateRoot, "latest-execution.json")
			writeJournalFile(t, latestPath, committing)
			writeJournalFile(t, filepath.Join(m.StateRoot, "transactions", final.PlanID, "execution.json"), transaction)
			before, _ := os.ReadFile(latestPath)
			restarted := New(m.StateRoot)
			if err := restarted.Register(a); err != nil {
				t.Fatal(err)
			}
			recovery, err := restarted.Recover(context.Background())
			if !errors.Is(err, ErrExecutionJournal) || recovery.State != "journal-recovery-required" {
				t.Fatal(recovery, err)
			}
			if after, _ := os.ReadFile(latestPath); string(after) != string(before) {
				t.Fatal("unprovable evidence was rewritten")
			}
		})
	}
}
