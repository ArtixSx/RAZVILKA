package app

import (
	"context"
	"log"
	"time"

	"github.com/ArtixSx/razvilka/internal/nodestore"
)

// Community feeds and subscriptions rotate windows of candidates. Expired
// copies are no longer eligible for the autopilot, but they still occupy the
// bounded private catalogue: once it is full every later import fails with
// FEED_CAPACITY, all origins expire and the autopilot has nothing to check.
// Only expired, enabled, unreferenced records received exclusively from feeds
// are removed; manual and legacy imports and disabled records are kept.
const (
	feedPrunePressure = nodestore.MaxNodes * 3 / 4
	feedPruneGrace    = time.Hour
	feedPruneInterval = 10 * time.Minute
)

// The caller holds exclusive operation admission, which protects references
// in the config, autopilot and dataplane journals during the batch.
func (a *App) pruneExpiredFeedNodes(ctx context.Context, now time.Time) (int, error) {
	if a.Nodes == nil || ctx.Err() != nil {
		return 0, nil
	}
	a.autonomy.mu.Lock()
	if !a.autonomy.feedPruneAt.IsZero() && now.Before(a.autonomy.feedPruneAt.Add(feedPruneInterval)) {
		a.autonomy.mu.Unlock()
		return 0, nil
	}
	a.autonomy.feedPruneAt = now
	a.autonomy.mu.Unlock()
	snapshot, err := a.Nodes.Snapshot(ctx, now)
	if err != nil || len(snapshot.Nodes) < feedPrunePressure {
		return 0, err
	}
	protected, err := a.protectedCleanupNodes(ctx, snapshot)
	if err != nil {
		return 0, err
	}
	ids := expiredFeedNodeIDs(snapshot, protected, now)
	if len(ids) == 0 {
		return 0, nil
	}
	if _, err := a.Nodes.DeleteBatch(ctx, ids, snapshot.Generation, now); err != nil {
		return 0, err
	}
	log.Printf("node catalogue: removed %d expired feed candidates (%d of %d slots were used)", len(ids), len(snapshot.Nodes), nodestore.MaxNodes)
	return len(ids), nil
}

func expiredFeedNodeIDs(snapshot nodestore.Snapshot, protected map[string]string, now time.Time) []string {
	kinds := map[string]string{}
	for _, s := range snapshot.Sources {
		kinds[s.ID] = s.Kind
	}
	ids := []string{}
	for _, n := range snapshot.Nodes {
		if n.Disabled || n.State != "expired" || len(n.Origins) == 0 || protected[n.ID] != "" {
			continue
		}
		feedOnly := true
		for _, o := range n.Origins {
			kind := kinds[o.SourceID]
			if kind != "community" && kind != "subscription" || now.Before(o.ExpiresAt.Add(feedPruneGrace)) {
				feedOnly = false
				break
			}
		}
		if feedOnly {
			ids = append(ids, n.ID)
		}
	}
	return ids
}
