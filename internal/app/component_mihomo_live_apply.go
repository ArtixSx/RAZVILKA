package app

import (
	"context"
	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/operationgate"
)

// Held only for an unconfirmed original Apply, never for an ACTIVE runtime.
type mihomoLiveApplyRetention struct {
	manager *dataplane.Manager
	context context.Context
	cleanup *operationgate.ExclusiveCleanupReview
	release func()
}

func (a *App) applyMihomoDataplane(ctx context.Context, plan dataplane.Plan, commit func() (func() error, error)) (dataplane.Execution, error) {
	a.mihomoProbe.liveStopMu.Lock()
	defer a.mihomoProbe.liveStopMu.Unlock()
	if a.mihomoProbe.liveApply != nil || a.mihomoProbe.liveStop != nil || !a.mihomoProbeRegistered() {
		return dataplane.Execution{}, dataplane.ErrReviewChanged
	}
	held, release, err := a.privateExclusiveOperation(ctx)
	if err != nil {
		return dataplane.Execution{}, err
	}
	cleanup, err := a.Operations.ReviewExclusiveCleanup(held)
	if err != nil {
		release()
		return dataplane.Execution{}, err
	}
	holder := &mihomoLiveApplyRetention{manager: a.Dataplane, context: context.WithoutCancel(held), cleanup: cleanup, release: release}
	returned := false
	defer func() {
		if !returned || holder.manager.HasPendingMihomoLive() {
			a.mihomoProbe.liveApply = holder
			a.Operations.FenceJournal()
		} else {
			release()
		}
	}()
	execution, err := holder.manager.Apply(held, plan, commit)
	returned = true
	return execution, err
}
