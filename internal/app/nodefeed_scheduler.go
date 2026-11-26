package app

import (
	"context"
	"slices"
	"time"

	"github.com/ArtixSx/razvilka/internal/operationgate"
)

func (a *App) StartNodeFeeds(ctx context.Context) {
	if a.NodeFeeds != nil {
		a.NodeFeeds.StartManagedWithSyncObserver(operationgate.WithLabel(ctx, "обновление подписок"), a.Operations.Enter, a.autonomySourceImported)
	}
}

func (a *App) autonomySourceImported(sourceID string) {
	if a.Store == nil {
		return
	}
	cfg := a.Store.Get()
	now := time.Now()
	a.autonomy.mu.Lock()
	doc := a.autonomy.doc
	interested := false
	if !a.autonomy.blocked && a.autonomyRouteBlockReason(doc.Policy, cfg) == "" && slices.Contains(doc.Policy.SourceIDs, sourceID) {
		for id, s := range doc.Services {
			r := doc.Runtime[id]
			if !s.Enabled || s.Removing || !cfg.Services[id].Enabled || cfg.AppliedServices[id].Enabled {
				continue
			}
			// The import callback runs after releasing its lease. A worker may
			// already be checking when the callback arrives. Latch one wake
			// without granting eligibility or clearing an existing retry.
			empty := r.Search != nil && len(r.Search.Ordered) == 0 && r.Search.Cursor == 0 &&
				r.Search.Exhausted && !r.Search.Halted && !now.Before(r.Search.RetryAt)
			if r.State == "searching" && empty || r.State == "checking" && (r.Search == nil || empty) {
				interested = true
				break
			}
		}
	}
	a.autonomy.mu.Unlock()
	if interested {
		a.wakeAutonomy()
	}
}
func (a *App) WaitNodeFeeds(ctx context.Context) error {
	if a.NodeFeeds == nil {
		return nil
	}
	return a.NodeFeeds.Wait(ctx)
}
