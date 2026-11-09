package app

import (
	"context"
	"errors"

	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/operationgate"
)

// dataplaneExecutionMutated reports whether any adapter step that can change
// the network was attempted. Rollback without readback after it is unproven.
func dataplaneExecutionMutated(execution dataplane.Execution) bool {
	for _, step := range execution.Steps {
		if step.Phase == "activate" || step.Phase == "deactivate" || step.Phase == "commit-adapter" {
			return true
		}
	}
	return false
}

// Callers retain their existing exclusive admission until this returns. Every
// application path, including background repair and Stop, uses the same fence:
// an unconfirmed rollback cannot be followed by another admitted mutation.
// A fence never releases the current lease or interrupts rollback cleanup.
func (a *App) applyDataplane(ctx context.Context, plan dataplane.Plan, commit func() (func() error, error)) (dataplane.Execution, error) {
	return a.applyDataplaneOriginal(ctx, plan, commit, nil)
}

// Only the original managed NFQ issuer supplies this private pending frame.
func (a *App) applyDataplaneOriginal(ctx context.Context, plan dataplane.Plan, commit func() (func() error, error), pending *managedNFQPendingFrame) (dataplane.Execution, error) {
	if a.Operations.Snapshot().Fenced {
		return dataplane.Execution{}, operationgate.ErrRecovery
	}
	if a.Dataplane == nil {
		return dataplane.Execution{}, errors.New("dataplane is unavailable")
	}
	var execution dataplane.Execution
	var err error
	if mihomoLivePlan(plan) {
		execution, err = a.applyMihomoDataplane(ctx, plan, commit)
	} else {
		execution, err = a.Dataplane.Apply(ctx, plan, commit)
	}
	if execution.State == "rollback-failed" || errors.Is(err, dataplane.ErrExecutionJournal) {
		if pending == nil || !pending.retain(ctx, a, plan) {
			a.Operations.FenceJournal()
		}
	}
	return execution, err
}
