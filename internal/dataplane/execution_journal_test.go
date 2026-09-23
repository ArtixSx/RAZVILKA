package dataplane

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

type journalFaultAdapter struct {
	*networkExecutionAdapter
}

func TestExecutionJournalRestartDoesNotEraseRecoveryBarrier(t *testing.T) {
	for _, state := range []string{"applying", "committing", "rolling-back", "rollback-failed", "journal-failed", "unknown", "mismatch", "missing-transaction", "corrupt", "running-step", "bad-path"} {
		t.Run(state, func(t *testing.T) {
			root := t.TempDir()
			m := New(root)
			plan := journalTestPlan()
			plan.State = "committed"
			if err := m.Record(plan); err != nil {
				t.Fatal(err)
			}
			execution := Execution{PlanID: plan.PlanID, Digest: plan.Digest, State: "committed", StartedAt: time.Now().UTC().Format(time.RFC3339Nano), FinishedAt: time.Now().UTC().Format(time.RFC3339Nano)}
			transactionRoot := filepath.Join(root, "transactions", plan.PlanID)
			if err := m.prepareExecutionRoot(transactionRoot); err != nil {
				t.Fatal(err)
			}
			switch state {
			case "mismatch", "missing-transaction", "corrupt":
			case "running-step":
				execution.Steps = []ExecutionStep{{Adapter: "sing-box", Phase: "rollback", State: "running"}}
			case "bad-path":
				execution.PlanID = "../outside"
			default:
				execution.State = state
			}
			if err := m.writeExecution(transactionRoot, execution); err != nil {
				t.Fatal(err)
			}
			switch state {
			case "mismatch":
				execution.State = "rolled-back"
				data, _ := json.Marshal(execution)
				if err := os.WriteFile(filepath.Join(transactionRoot, "execution.json"), data, 0o600); err != nil {
					t.Fatal(err)
				}
			case "missing-transaction":
				if err := os.Remove(filepath.Join(transactionRoot, "execution.json")); err != nil {
					t.Fatal(err)
				}
			case "corrupt":
				if err := os.WriteFile(filepath.Join(root, "latest-execution.json"), []byte("{"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			before, err := os.ReadFile(filepath.Join(root, "latest-execution.json"))
			if err != nil {
				t.Fatal(err)
			}
			// A fresh Manager has no in-memory fence from the previous process.
			restarted := New(root)
			adapter := &fakeAdapter{id: "sing-box"}
			if err := restarted.Register(adapter); err != nil {
				t.Fatal(err)
			}
			recovery, err := restarted.Recover(context.Background())
			if !errors.Is(err, ErrExecutionJournal) || recovery.State != "journal-recovery-required" || !recovery.Guarded || len(adapter.calls) != 0 {
				t.Fatal(recovery, err, adapter.calls)
			}
			_, err = restarted.Apply(context.Background(), journalTestPlan(), func() (func() error, error) { t.Fatal("restart applied candidate"); return nil, nil })
			if !errors.Is(err, ErrExecutionJournal) || len(adapter.calls) != 0 {
				t.Fatal(err, adapter.calls)
			}
			after, err := os.ReadFile(filepath.Join(root, "latest-execution.json"))
			if err != nil || string(after) != string(before) {
				t.Fatal("recovery evidence overwritten", err)
			}
		})
	}
}

func TestExecutionJournalCompletedTransactionAllowsRecovery(t *testing.T) {
	for _, rollback := range []bool{false, true} {
		t.Run(map[bool]string{false: "committed", true: "rolled-back"}[rollback], func(t *testing.T) {
			m := New(t.TempDir())
			a := &fakeAdapter{id: "sing-box"}
			if err := m.Register(a); err != nil {
				t.Fatal(err)
			}
			plan := journalTestPlan()
			if _, err := m.Apply(context.Background(), plan, nil); err != nil {
				t.Fatal(err)
			}
			if rollback {
				a.failAt = "health"
				plan.PlanID = "dp-candidate"
				if execution, err := m.Apply(context.Background(), plan, nil); err == nil || execution.State != "rolled-back" {
					t.Fatal(execution, err)
				}
				a.failAt = ""
			}
			restarted := New(m.StateRoot)
			if err := restarted.Register(a); err != nil {
				t.Fatal(err)
			}
			recovery, err := restarted.Recover(context.Background())
			if err != nil || recovery.State != "recovered" || !a.recovered {
				t.Fatal(recovery, err)
			}
		})
	}
}

func (a *journalFaultAdapter) Rollback(context.Context, Plan, string) error {
	return a.phase("rollback")
}

func journalTestPlan() Plan {
	return Plan{SchemaVersion: SchemaVersion, PlanID: "dp-journal", Digest: strings.Repeat("a", 64), Ready: true, Adapters: []string{"sing-box"}}
}

// A non-empty directory gives the same write refusal on Windows and Linux,
// including privileged CI runners where chmod alone would not deny a write.
func blockJournalFile(t *testing.T, path string) {
	t.Helper()
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	if err := os.MkdirAll(path, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(path, "unrelated"), []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestExecutionJournalMustBeWritableBeforeAdaptersRun(t *testing.T) {
	for _, target := range []string{"latest-execution.json", "transactions/dp-journal/execution.json", "latest-committed-plan.json"} {
		t.Run(target, func(t *testing.T) {
			m := New(t.TempDir())
			a := &fakeAdapter{id: "sing-box"}
			if err := m.Register(a); err != nil {
				t.Fatal(err)
			}
			blockJournalFile(t, filepath.Join(m.StateRoot, target))
			execution, err := m.Apply(context.Background(), journalTestPlan(), func() (func() error, error) {
				t.Fatal("config was changed without journal")
				return nil, nil
			})
			if !errors.Is(err, ErrExecutionJournal) || execution.State != "journal-failed" || len(a.calls) != 0 {
				t.Fatal(execution, err, a.calls)
			}
		})
	}
}

func TestExecutionJournalFailureStopsNextPhaseButCannotStopCleanup(t *testing.T) {
	for _, phase := range []string{"snapshot", "stage", "validate", "canary", "activate", "health", "commit-adapter", "rollback"} {
		for _, target := range []string{"latest-execution.json", "transactions/dp-journal/execution.json"} {
			t.Run(phase+"/"+target, func(t *testing.T) {
				m := New(t.TempDir())
				prior := journalTestPlan()
				prior.PlanID, prior.State = "dp-previous", "committed"
				if err := m.Record(prior); err != nil {
					t.Fatal(err)
				}
				a := &journalFaultAdapter{&networkExecutionAdapter{fakeAdapter: &fakeAdapter{id: "sing-box"}, after: func(current string) error {
					if current == phase {
						blockJournalFile(t, filepath.Join(m.StateRoot, target))
					}
					if phase == "rollback" && current == "health" {
						return errors.New("service failed")
					}
					return nil
				}}}
				if err := m.Register(a); err != nil {
					t.Fatal(err)
				}
				execution, err := m.Apply(context.Background(), journalTestPlan(), func() (func() error, error) {
					t.Fatal("config commit ran after journal failure")
					return nil, nil
				})
				want := "rollback-failed"
				if phase == "canary" {
					want = "canary-failed"
				}
				if !errors.Is(err, ErrExecutionJournal) || execution.State != want {
					t.Fatal(execution, err)
				}
				cleanupRequired := phase != "snapshot" && phase != "canary"
				if slices.Contains(a.calls, "rollback") != cleanupRequired {
					t.Fatal("incorrect cleanup", a.calls)
				}
				failedIndex := slices.Index(a.calls, phase)
				for _, later := range a.calls[failedIndex+1:] {
					if later != "rollback" {
						t.Fatal("phase ran after journal failure", a.calls)
					}
				}
				committed, exists, readErr := m.Committed()
				if readErr != nil || !exists || committed.PlanID != prior.PlanID {
					t.Fatal("previous recovery source changed", committed, readErr)
				}
				if data, err := os.ReadFile(filepath.Join(m.StateRoot, target, "unrelated")); err != nil || string(data) != "keep" {
					t.Fatal("journal error removed unrelated data", err)
				}
			})
		}
	}
}

func TestExecutionJournalFailureRollsBackEveryAdapterAndConfiguration(t *testing.T) {
	m := New(t.TempDir())
	first, second := &fakeAdapter{id: "first"}, &fakeAdapter{id: "second"}
	for _, a := range []*fakeAdapter{first, second} {
		if err := m.Register(a); err != nil {
			t.Fatal(err)
		}
	}
	plan := journalTestPlan()
	plan.Adapters = []string{"first", "second"}
	changed := false
	execution, err := m.Apply(context.Background(), plan, func() (func() error, error) {
		changed = true
		blockJournalFile(t, filepath.Join(m.StateRoot, "latest-execution.json"))
		return func() error { changed = false; return nil }, nil
	})
	if !errors.Is(err, ErrExecutionJournal) || execution.State != "rollback-failed" || changed || !first.rollback || !second.rollback {
		t.Fatal(execution, err, changed, first.calls, second.calls)
	}
}

func TestExecutionJournalNoopCommitFailureRestoresConfiguration(t *testing.T) {
	for _, target := range []string{"latest-plan.json", "latest-committed-plan.json"} {
		t.Run(target, func(t *testing.T) {
			m := New(t.TempDir())
			prior := journalTestPlan()
			prior.PlanID, prior.State = "dp-previous", "committed"
			if err := m.Record(prior); err != nil {
				t.Fatal(err)
			}
			plan := journalTestPlan()
			plan.Noop, plan.Adapters = true, nil
			changed := false
			path := filepath.Join(m.StateRoot, target)
			execution, err := m.Apply(context.Background(), plan, func() (func() error, error) {
				changed = true
				blockJournalFile(t, path)
				return func() error {
					changed = false
					// Simulate storage becoming writable again during cleanup.
					if err := os.Remove(filepath.Join(path, "unrelated")); err != nil {
						return err
					}
					return os.Remove(path)
				}, nil
			})
			if !errors.Is(err, ErrExecutionJournal) || execution.State != "rolled-back" || changed {
				t.Fatal(execution, err, changed)
			}
			committed, exists, readErr := m.Committed()
			if readErr != nil || !exists || committed.PlanID != prior.PlanID {
				t.Fatal("lost previous committed plan", committed, readErr)
			}
		})
	}
}

func TestCommittedJournalPreservesLegacyAndRestoresUncertainPublication(t *testing.T) {
	for _, previous := range []string{"absent", "legacy", "current"} {
		t.Run(previous, func(t *testing.T) {
			m := New(t.TempDir())
			prior := journalTestPlan()
			prior.PlanID, prior.State = "dp-previous", "committed"
			if previous != "absent" {
				if err := m.Record(prior); err != nil {
					t.Fatal(err)
				}
				if previous == "legacy" {
					if err := os.Remove(filepath.Join(m.StateRoot, "latest-committed-plan.json")); err != nil {
						t.Fatal(err)
					}
				}
			}
			restore, err := m.preserveCommittedJournal()
			if err != nil {
				t.Fatal(err)
			}
			candidate := journalTestPlan()
			candidate.State = "committed"
			if err := m.recordLocked(candidate); err != nil {
				t.Fatal(err)
			}
			// A write can fail after publishing. Restore must replace or remove
			// the candidate even if the caller received no successful commit.
			if err := restore(); err != nil {
				t.Fatal(err)
			}
			candidate.State = "rolled-back"
			if err := m.recordLocked(candidate); err != nil {
				t.Fatal(err)
			}
			committed, exists, err := m.Committed()
			if err != nil || exists != (previous != "absent") || (exists && committed.PlanID != prior.PlanID) {
				t.Fatal(committed, exists, err)
			}
		})
	}
}
