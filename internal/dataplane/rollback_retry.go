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
	if guard == nil || len(planID) != 19 || !strings.HasPrefix(planID, "dp-") || strings.Trim(planID[3:], "0123456789abcdef") != "" || len(digest) != 64 || strings.Trim(digest, "0123456789abcdef") != "" {
		return refuse()
	}
	if err := m.beginOperation(ctx); err != nil {
		return Execution{}, err
	}
	defer m.endOperation()
	var latest, transaction *Execution
	found, err := readOptionalJournal(filepath.Join(m.StateRoot, "latest-execution.json"), &latest)
	if err != nil || !found || latest == nil || latest.State != "rollback-failed" || latest.PlanID != planID || latest.Digest != digest || latest.FinishedAt == "" || len(latest.Steps) > 96 {
		return refuse()
	}
	root := filepath.Join(m.StateRoot, "transactions", planID)
	found, err = readOptionalJournal(filepath.Join(root, "execution.json"), &transaction)
	if err != nil || !found || !reflect.DeepEqual(latest, transaction) {
		return refuse()
	}
	plan, found, err := m.latestLocked()
	if err != nil || !found || plan.PlanID != planID || plan.Digest != digest || plan.State != "rollback-failed" || plan.DNS != nil || plan.SuspendDNS || len(plan.RetiringAdapters) > 0 {
		return refuse()
	}
	previous, found, err := m.committedLocked()
	if err != nil || !found || previous.State != "committed" || previous.PlanID == planID || previous.DNS != nil || !slices.Equal(plan.Adapters, previous.Adapters) {
		return refuse()
	}
	prepared := []Adapter{}
	seen := map[string]bool{}
	failedBeforeCommit := false
	for _, step := range latest.Steps {
		if step.Phase == "rollback" || step.Phase == "verify-rollback" || step.Phase == "retry-rollback" || step.Phase == "retry-verify-rollback" {
			if !failedBeforeCommit {
				return refuse()
			}
			if !seen[step.Adapter] || step.State != "passed" && step.State != "failed" && step.State != "running" || step.State == "running" && !strings.HasPrefix(step.Phase, "retry-") || step.State != "running" && step.FinishedAt == "" {
				return refuse()
			}
			continue
		}
		if failedBeforeCommit || step.FinishedAt == "" {
			return refuse()
		}
		if step.Phase == "snapshot" {
			adapter, exists := m.adapter(step.Adapter)
			if !exists || seen[step.Adapter] || !slices.Contains([]string{"nfqws2", "sing-box"}, step.Adapter) || step.State != "passed" {
				return refuse()
			}
			if _, ok := adapter.(RollbackVerifier); !ok {
				return refuse()
			}
			seen[step.Adapter] = true
			prepared = append(prepared, adapter)
		}
		if step.State == "failed" {
			if !seen[step.Adapter] || !slices.Contains([]string{"activate", "health", "commit-adapter"}, step.Phase) {
				return refuse()
			}
			failedBeforeCommit = true
		} else if step.State != "passed" {
			return refuse()
		}
	}
	if !failedBeforeCommit || len(prepared) == 0 || len(prepared) != len(plan.Adapters) {
		return refuse()
	}
	if err := guard(previous); err != nil {
		return refuse()
	}
	if err := ctx.Err(); err != nil {
		return Execution{}, err
	}
	execution := *latest
	execution.Steps = slices.Clone(latest.Steps)
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
	run := func(adapter Adapter, phase string, action func(context.Context, Plan, string) error) {
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
	}
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
	failure = errors.Join(failure, guard(previous))
	execution.FinishedAt = time.Now().UTC().Format(time.RFC3339Nano)
	if failure == nil {
		execution.State, plan.State = "rolled-back", "rolled-back"
		execution.RollbackVerified = true
		plan.Note = "The recorded rollback was retried and its owned runtime was verified. Service access still requires a fresh check."
	} else {
		execution.Error += "; retry rollback: " + failure.Error()
	}
	if err := errors.Join(m.recordLocked(plan), m.writeExecution(root, execution)); err != nil {
		execution.State, plan.State = "rollback-failed", "rollback-failed"
		execution.RollbackVerified = false
		failure = errors.Join(failure, err, m.recordLocked(plan), m.writeExecution(root, execution))
	}
	if failure != nil {
		return execution, fmt.Errorf("rollback retry failed: %w", failure)
	}
	return execution, nil
}
