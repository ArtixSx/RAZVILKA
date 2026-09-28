package dataplane

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"time"
)

// RetryFailedRollback is explicit recovery of an intact, finished rollback
// journal, not permission to erase a fence. The first implementation supports
// NFQWS2/Sing-box failures before the configuration commit. The caller must
// hold the application's OS state lease and confirm the saved applied settings.
func (m *Manager) RetryFailedRollback(ctx context.Context, planID, digest string, guard func(Plan) error) (Execution, error) {
	refuse := func() (Execution, error) {
		return Execution{}, executionJournalError(errors.New("rollback retry requires matching reviewed journals and applied settings"))
	}
	if guard == nil || !validPlanID(planID) || !validPlanDigest(digest) {
		return refuse()
	}
	if err := m.beginOperation(ctx); err != nil {
		return Execution{}, err
	}
	defer m.endOperation()
	reviewed, ok := m.reviewFailedRollback(planID, digest)
	if !ok {
		return refuse()
	}
	for _, adapter := range reviewed.prepared {
		if _, ok := adapter.(RollbackVerifier); !ok {
			return refuse()
		}
	}
	if err := guard(reviewed.previous); err != nil {
		return refuse()
	}
	return m.runFailedRollbackRecovery(ctx, reviewed, guard, "retry rollback", "rollback retry failed", func(run recoveryStepRunner) {
		prepared := reviewed.prepared
		for i := len(prepared) - 1; i >= 0; i-- {
			run(prepared[i], "retry-rollback", prepared[i].Rollback)
		}
		for _, adapter := range prepared {
			run(adapter, "retry-verify-rollback", func(c context.Context, p Plan, path string) error {
				confirmed, err := adapter.(RollbackVerifier).VerifyRollback(c, p, path)
				if !confirmed {
					err = errors.Join(err, errors.New("restored runtime is not confirmed"))
				}
				return errors.Join(err, c.Err())
			})
		}
	}, func(execution *Execution, plan *Plan) {
		execution.RollbackVerified = true
		plan.Note = "The recorded rollback was retried and its owned runtime was verified. Service access still requires a fresh check."
	})
}

// CloseFailedRollback ends a rollback-failed record that can no longer be
// retried, typically after a reboot removed the processes and interfaces its
// snapshot recorded, so VerifyRollback cannot match them again. It accepts the
// same reviewed journals as RetryFailedRollback, then deactivates every
// adapter of the failed plan under that adapter's own ownership checks. Only
// when all of them succeed is the execution recorded as rolled-back, with
// RollbackVerified=false: this proves no owned runtime remains, not that the
// previous route works. The committed plan must be recovered and checked
// again. The caller must hold the application's OS state lease and confirm the
// saved applied settings.
func (m *Manager) CloseFailedRollback(ctx context.Context, planID, digest string, guard func(Plan) error) (Execution, error) {
	refuse := func() (Execution, error) {
		return Execution{}, executionJournalError(errors.New("closing a failed rollback requires matching reviewed journals and applied settings"))
	}
	if guard == nil || !validPlanID(planID) || !validPlanDigest(digest) {
		return refuse()
	}
	if err := m.beginOperation(ctx); err != nil {
		return Execution{}, err
	}
	defer m.endOperation()
	reviewed, ok := m.reviewFailedRollback(planID, digest)
	if !ok {
		return refuse()
	}
	for _, adapter := range reviewed.prepared {
		if _, ok := adapter.(RuntimeDeactivator); !ok {
			return refuse()
		}
	}
	if err := guard(reviewed.previous); err != nil {
		return refuse()
	}
	return m.runFailedRollbackRecovery(ctx, reviewed, guard, "close failed rollback", "closing failed rollback failed", func(run recoveryStepRunner) {
		prepared := reviewed.prepared
		for i := len(prepared) - 1; i >= 0; i-- {
			deactivator := prepared[i].(RuntimeDeactivator)
			run(prepared[i], "close-deactivate", func(c context.Context, _ Plan, _ string) error {
				return errors.Join(deactivator.Deactivate(c), c.Err())
			})
		}
	}, func(execution *Execution, plan *Plan) {
		execution.RollbackVerified = false
		execution.Error += "; closed after every owned runtime was deactivated; the previous route is not verified"
		plan.Note = "The failed rollback was closed after its owned runtime was deactivated. Recover and check the committed plan again before claiming service access."
	})
}

// failedRollback is a reviewed rollback-failed journal: intact, finished and
// limited to NFQWS2/Sing-box failures before the configuration commit.
type failedRollback struct {
	latest   *Execution
	root     string
	plan     Plan
	previous Plan
	prepared []Adapter
}

// reviewFailedRollback validates the journals while the caller holds the
// dataplane operation. Any doubt refuses.
func (m *Manager) reviewFailedRollback(planID, digest string) (failedRollback, bool) {
	var latest, transaction *Execution
	found, err := readOptionalJournal(filepath.Join(m.StateRoot, "latest-execution.json"), &latest)
	if err != nil || !found || latest == nil || latest.State != "rollback-failed" || latest.PlanID != planID || latest.Digest != digest || latest.FinishedAt == "" || len(latest.Steps) > 96 {
		return failedRollback{}, false
	}
	root := filepath.Join(m.StateRoot, "transactions", planID)
	found, err = readOptionalJournal(filepath.Join(root, "execution.json"), &transaction)
	if err != nil || !found || !reflect.DeepEqual(latest, transaction) {
		return failedRollback{}, false
	}
	plan, found, err := m.latestLocked()
	if err != nil || !found || plan.PlanID != planID || plan.Digest != digest || plan.State != "rollback-failed" || plan.DNS != nil || plan.SuspendDNS || len(plan.RetiringAdapters) > 0 {
		return failedRollback{}, false
	}
	previous, found, err := m.committedLocked()
	if err != nil || !found || previous.State != "committed" || previous.PlanID == planID || previous.DNS != nil || !slices.Equal(plan.Adapters, previous.Adapters) {
		return failedRollback{}, false
	}
	prepared := []Adapter{}
	seen := map[string]bool{}
	failedBeforeCommit := false
	for _, step := range latest.Steps {
		if recovery, resumable := rollbackRecoveryPhase(step.Phase); recovery {
			if !failedBeforeCommit {
				return failedRollback{}, false
			}
			if !seen[step.Adapter] || step.State != "passed" && step.State != "failed" && step.State != "running" || step.State == "running" && !resumable || step.State != "running" && step.FinishedAt == "" {
				return failedRollback{}, false
			}
			continue
		}
		if failedBeforeCommit || step.FinishedAt == "" {
			return failedRollback{}, false
		}
		if step.Phase == "snapshot" {
			adapter, exists := m.adapter(step.Adapter)
			if !exists || seen[step.Adapter] || !slices.Contains([]string{"nfqws2", "sing-box"}, step.Adapter) || !slices.Contains(plan.Adapters, step.Adapter) || step.State != "passed" {
				return failedRollback{}, false
			}
			seen[step.Adapter] = true
			prepared = append(prepared, adapter)
		}
		if step.State == "failed" {
			if !seen[step.Adapter] || !slices.Contains([]string{"activate", "health", "commit-adapter"}, step.Phase) {
				return failedRollback{}, false
			}
			failedBeforeCommit = true
		} else if step.State != "passed" {
			return failedRollback{}, false
		}
	}
	if !failedBeforeCommit || len(prepared) == 0 || len(prepared) != len(plan.Adapters) {
		return failedRollback{}, false
	}
	return failedRollback{latest: latest, root: root, plan: plan, previous: previous, prepared: prepared}, true
}

// rollbackRecoveryPhase reports whether a step belongs to the rollback after
// the failure, and whether it came from a later explicit recovery that may
// have been interrupted while running.
func rollbackRecoveryPhase(phase string) (recovery, resumable bool) {
	switch phase {
	case "rollback", "verify-rollback":
		return true, false
	case "retry-rollback", "retry-verify-rollback", "close-deactivate":
		return true, true
	}
	return false, false
}

type recoveryStepRunner func(adapter Adapter, phase string, action func(context.Context, Plan, string) error)

// runFailedRollbackRecovery journals each step before and after it runs and
// records the outcome. succeed marks the result only when every step and the
// final guard passed; otherwise the record stays rollback-failed.
func (m *Manager) runFailedRollbackRecovery(ctx context.Context, reviewed failedRollback, guard func(Plan) error, label, failedMessage string, steps func(recoveryStepRunner), succeed func(*Execution, *Plan)) (Execution, error) {
	if err := ctx.Err(); err != nil {
		return Execution{}, err
	}
	plan, root := reviewed.plan, reviewed.root
	execution := *reviewed.latest
	execution.Steps = slices.Clone(reviewed.latest.Steps)
	execution.RollbackVerified = false
	for i := range execution.Steps {
		if execution.Steps[i].State == "running" {
			execution.Steps[i].State = "failed"
			execution.Steps[i].Detail = "Earlier recovery was interrupted before its outcome could be confirmed."
			execution.Steps[i].FinishedAt = time.Now().UTC().Format(time.RFC3339Nano)
		}
	}
	recovery, cancel := context.WithTimeout(context.WithoutCancel(ctx), m.rollbackTimeout())
	defer cancel()
	var failure error
	steps(func(adapter Adapter, phase string, action func(context.Context, Plan, string) error) {
		step := ExecutionStep{Adapter: adapter.ID(), Phase: phase, State: "running", StartedAt: time.Now().UTC().Format(time.RFC3339Nano)}
		execution.Steps = append(execution.Steps, step)
		index := len(execution.Steps) - 1
		failure = errors.Join(failure, m.writeExecution(root, execution))
		err := action(recovery, plan, filepath.Join(root, adapter.ID()))
		execution.Steps[index].FinishedAt = time.Now().UTC().Format(time.RFC3339Nano)
		execution.Steps[index].State = "passed"
		if err != nil {
			execution.Steps[index].State = "failed"
			execution.Steps[index].Detail = err.Error()
		}
		failure = errors.Join(failure, err, m.writeExecution(root, execution))
	})
	failure = errors.Join(failure, guard(reviewed.previous))
	execution.FinishedAt = time.Now().UTC().Format(time.RFC3339Nano)
	if failure == nil {
		execution.State, plan.State = "rolled-back", "rolled-back"
		succeed(&execution, &plan)
	} else {
		execution.Error += "; " + label + ": " + failure.Error()
	}
	if err := errors.Join(m.recordLocked(plan), m.writeExecution(root, execution)); err != nil {
		execution.State, plan.State = "rollback-failed", "rollback-failed"
		execution.RollbackVerified = false
		failure = errors.Join(failure, err, m.recordLocked(plan), m.writeExecution(root, execution))
	}
	if failure != nil {
		return execution, fmt.Errorf("%s: %w", failedMessage, failure)
	}
	return execution, nil
}

// validPlanID matches the "dp-" + 16 lowercase hex form produced by BuildAt.
func validPlanID(id string) bool {
	return len(id) == 19 && strings.HasPrefix(id, "dp-") && strings.Trim(id[3:], "0123456789abcdef") == ""
}

func validPlanDigest(digest string) bool {
	return len(digest) == 64 && strings.Trim(digest, "0123456789abcdef") == ""
}
