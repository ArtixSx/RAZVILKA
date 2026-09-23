package app

import (
	"context"
	"errors"

	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/operationgate"
)

// Callers retain their existing exclusive admission until this returns. Every
// application path, including background repair and Stop, uses the same fence:
// an unconfirmed rollback cannot be followed by another admitted mutation.
// A fence never releases the current lease or interrupts rollback cleanup.
func (a *App) applyDataplane(ctx context.Context, plan dataplane.Plan, commit func() (func() error, error)) (dataplane.Execution, error) {
	if a.Operations.Snapshot().Fenced {
		return dataplane.Execution{}, operationgate.ErrRecovery
	}
	if a.Dataplane == nil {
		return dataplane.Execution{}, errors.New("dataplane is unavailable")
	}
	execution, err := a.Dataplane.Apply(ctx, plan, commit)
	if execution.State == "rollback-failed" {
		a.Operations.Fence()
	}
	return execution, err
}
