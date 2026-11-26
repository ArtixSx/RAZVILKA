package app

import (
	"context"
	"log"
	"slices"
	"time"

	"github.com/ArtixSx/razvilka/internal/nodestore"
)

// Community feeds and subscriptions rotate windows of candidates. Expired
// copies are no longer eligible for the autopilot, yet still
// occupy the bounded private catalogue. Once it is full every later import
// fails with FEED_CAPACITY and the autopilot has nothing new to check.
// Only enabled, unreferenced records received exclusively from feeds are
// removed; manual and legacy imports and disabled records are kept. A feed
// may send a removed candidate again; it is then checked afresh.
const (
	feedPrunePressure = nodestore.MaxNodes * 3 / 4
	feedPruneGrace    = time.Hour
	feedPruneInterval = 10 * time.Minute
	// Two community feeds bring up to 32 candidates each every two hours,
	// while the autopilot checks about two every five minutes. On the owner's
	// router 376 of 398 records had never been checked and the catalogue was
	// heading for FEED_CAPACITY, where newer, possibly working candidates can
	// no longer be imported. Only this many never-checked feed candidates are
	// kept; the ones their feeds sent longest ago go first and come back if a
	// feed sends them again.
	feedUncheckedBudget = 96
)

// The caller holds exclusive operation admission, which protects references
// in the config, autopilot and dataplane journals during the batch.
func (a *App) pruneExpiredFeedNodes(ctx context.Context, now time.Time) (removed int, pruneErr error) {
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
	defer func() { a.recordFeedPruneOutcome(pruneErr) }()
	snapshot, err := a.Nodes.Snapshot(ctx, now)
	if err != nil {
		return 0, err
	}
	protected, err := a.protectedCleanupNodes(ctx, snapshot)
	if err != nil {
		return 0, err
	}
	// General connectivity lives only in RAM and therefore has no service
	// CheckRecord. Do not evict a warm reserve as never checked.
	a.nodeReadiness.mu.Lock()
	for id, e := range a.nodeReadiness.entries {
		if e.ready(now) || (a.nodeReadiness.cancel != nil && id == a.nodeReadiness.cursor) {
			protected[id] = "readiness"
		}
	}
	a.nodeReadiness.mu.Unlock()
	var expired []string
	if len(snapshot.Nodes) >= feedPrunePressure {
		expired = expiredFeedCandidates(snapshot, protected, now)
	}
	unchecked := feedUncheckedExcess(snapshot, protected, expired)
	ids := append(expired, unchecked...)
	if len(ids) == 0 {
		return 0, nil
	}
	if _, err := a.Nodes.DeleteBatch(ctx, ids, snapshot.Generation, now); err != nil {
		return 0, err
	}
	log.Printf("node catalogue: removed %d expired and %d long-unchecked feed candidates (%d of %d slots were used)", len(expired), len(unchecked), len(snapshot.Nodes), nodestore.MaxNodes)
	return len(ids), nil
}

// Report only transitions from actual attempts; interval/context skips cannot
// clear a failure. Never publish storage errors, node identities or endpoints.
func (a *App) recordFeedPruneOutcome(err error) {
	a.autonomy.mu.Lock()
	previous := a.autonomy.feedPruneFailed
	a.autonomy.feedPruneFailed = err != nil
	a.autonomy.mu.Unlock()
	if err != nil && !previous {
		log.Print("node catalogue: code=FEED_PRUNE_FAILED Не удалось завершить автоматическую очистку каталога; остальные сервисы продолжают работу.")
	} else if err == nil && previous {
		log.Print("node catalogue: code=FEED_PRUNE_RECOVERED Автоматическая очистка каталога снова доступна.")
	}
}

// feedUncheckedExcess lists never-checked, enabled, unreferenced feed-only
// records beyond feedUncheckedBudget, those last sent by a feed longest ago
// first. A record with any check, a manual origin or a reference is kept.
func feedUncheckedExcess(snapshot nodestore.Snapshot, protected map[string]string, removed []string) []string {
	kinds := map[string]string{}
	for _, s := range snapshot.Sources {
		kinds[s.ID] = s.Kind
	}
	type candidate struct {
		id          string
		seen, added time.Time
	}
	var queue []candidate
	for _, n := range snapshot.Nodes {
		if n.HasAlias || n.Disabled || len(n.Origins) == 0 || protected[n.ID] != "" || slices.Contains(removed, n.ID) || len(n.Health.History) != 0 || !n.Health.CheckedAt.IsZero() {
			continue
		}
		feedOnly, seen := true, time.Time{}
		for _, o := range n.Origins {
			if kind := kinds[o.SourceID]; kind != "community" && kind != "subscription" {
				feedOnly = false
			}
			if o.ReceivedAt.After(seen) {
				seen = o.ReceivedAt
			}
		}
		if feedOnly {
			queue = append(queue, candidate{n.ID, seen, n.AddedAt})
		}
	}
	if len(queue) <= feedUncheckedBudget {
		return nil
	}
	slices.SortStableFunc(queue, func(a, b candidate) int {
		if c := a.seen.Compare(b.seen); c != 0 {
			return c
		}
		return a.added.Compare(b.added)
	})
	ids := make([]string, 0, len(queue)-feedUncheckedBudget)
	for _, c := range queue[:len(queue)-feedUncheckedBudget] {
		ids = append(ids, c.id)
	}
	return ids
}

// Catalogue pressure never converts a single connectivity or service failure
// into deletion. Confirmed failures use the reviewed free-pool path.
func expiredFeedCandidates(snapshot nodestore.Snapshot, protected map[string]string, now time.Time) []string {
	var expired []string
	kinds := map[string]string{}
	for _, s := range snapshot.Sources {
		kinds[s.ID] = s.Kind
	}
	for _, n := range snapshot.Nodes {
		if n.HasAlias || n.Disabled || len(n.Origins) == 0 || protected[n.ID] != "" {
			continue
		}
		feedOnly, stale := true, true
		for _, o := range n.Origins {
			kind := kinds[o.SourceID]
			if kind != "community" && kind != "subscription" {
				feedOnly = false
			}
			if now.Before(o.ExpiresAt.Add(feedPruneGrace)) {
				stale = false
			}
		}
		if feedOnly && n.State == "expired" && stale {
			expired = append(expired, n.ID)
		}
	}
	return expired
}
