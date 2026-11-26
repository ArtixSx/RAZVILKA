package dataplane

import (
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"time"
)

type nfqws2RollbackHookContextKey struct{}

// Only the actual recovery writer issues this ephemeral owner after both
// execution records acknowledge its running NFQ retry step. Decoded journal
// fields alone never create it, and it expires before the step settles.
type nfqws2RollbackHookIntent struct {
	manager          *Manager
	adapter          *NFQWS2Adapter
	failed, previous Plan
	execution        Execution
	root             string
	guard            func(Plan) error
	active           bool
	priorUnconfirmed bool
}

func (m *Manager) nfqws2RollbackHookContext(ctx context.Context, reviewed failedRollback, execution Execution, adapter Adapter, guard func(Plan) error) (context.Context, func()) {
	nfq, actual := adapter.(*NFQWS2Adapter)
	registered, exists := m.adapter("nfqws2")
	if !actual || !exists || registered != nfq || !nfqws2HookPlan(reviewed.previous) || len(execution.Resources) != 0 || execution.ResourcePlanID != "" {
		return ctx, func() {}
	}
	execution.Steps = slices.Clone(execution.Steps)
	intent := &nfqws2RollbackHookIntent{manager: m, adapter: nfq, failed: reviewed.plan, previous: reviewed.previous, execution: execution, root: reviewed.root, guard: guard, active: true}
	// Compaction deliberately discards later recovery rows; missing history
	// cannot establish that every earlier firewall writer acknowledged effects.
	intent.priorUnconfirmed = strings.Contains(reviewed.latest.Error, "earlier recovery steps compacted")
	// Inspect the original reviewed image, before running steps are rewritten
	// or old recovery rows compacted. A matching FULL graph cannot prove who
	// issued an earlier interrupted or unacknowledged firewall effect.
	for _, step := range reviewed.latest.Steps {
		if step.Adapter == "nfqws2" && step.Phase == "retry-rollback" && step.State != "passed" {
			intent.priorUnconfirmed = true
		}
	}
	return context.WithValue(ctx, nfqws2RollbackHookContextKey{}, intent), func() { intent.active = false }
}

func (i *nfqws2RollbackHookIntent) current(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if i.priorUnconfirmed {
		return ErrNFQWS2HookUncertain
	}
	if !i.active || i.guard == nil || i.guard(i.previous) != nil {
		return ErrReviewChanged
	}
	registered, exists := i.manager.adapter("nfqws2")
	if !exists || registered != i.adapter {
		return ErrReviewChanged
	}
	for _, path := range []string{filepath.Join(i.manager.StateRoot, "latest-execution.json"), filepath.Join(i.root, "execution.json")} {
		var execution *Execution
		if exists, err := readOptionalJournal(path, &execution); err != nil || !exists || execution == nil || !reflect.DeepEqual(*execution, i.execution) {
			return errors.Join(ErrExecutionJournal, err)
		}
	}
	failed, exists, err := i.manager.latestLocked()
	if err != nil || !exists || !reflect.DeepEqual(failed, i.failed) {
		return errors.Join(ErrReviewChanged, err)
	}
	previous, exists, err := i.manager.committedLocked()
	if err != nil || !exists || !reflect.DeepEqual(previous, i.previous) {
		return errors.Join(ErrReviewChanged, err)
	}
	return ctx.Err()
}

// Caller already holds NFQ resources. An already restored running lease may
// have lost its hooks to firmware while a different adapter kept the global
// transaction fenced. Restore only its exact committed graph under the same
// durable retry intent, then let the unchanged rollback verifier decide.
func (a *NFQWS2Adapter) restoreRolledBackHooks(ctx context.Context, failed Plan, snapshot nfqws2Snapshot) error {
	intent, issued := ctx.Value(nfqws2RollbackHookContextKey{}).(*nfqws2RollbackHookIntent)
	if !issued || !snapshot.FirstStart || !snapshot.WasRunning {
		return nil
	}
	if intent.adapter != a || !reflect.DeepEqual(failed, intent.failed) {
		return ErrReviewChanged
	}
	if err := intent.current(ctx); err != nil {
		return err
	}
	lease, err := a.readLease()
	transaction, bound := a.firstStartTransaction(intent.previous)
	if err != nil || !bound || lease == nil || lease.Transaction != transaction || !nfqws2RollbackLeaseEqual(lease, snapshot.Lease) {
		return errors.Join(ErrReviewChanged, err)
	}
	bounded, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	result, err := a.restoreFirstStartHooksLocked(WithReviewGuard(bounded, intent.current), intent.previous, lease, intent.current)
	if result.Uncertain {
		return errors.Join(err, ErrNFQWS2HookUncertain)
	}
	return err
}
