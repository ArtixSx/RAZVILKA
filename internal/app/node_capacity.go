package app

import (
	"context"
	"log"
	"time"

	"github.com/ArtixSx/razvilka/internal/nodestore"
)

// Community feeds and subscriptions rotate windows of candidates. Expired
// copies are no longer eligible for the autopilot, and candidates that could
// not even connect or reach the internet cannot carry any service; both still
// occupy the bounded private catalogue. Once it is full every later import
// fails with FEED_CAPACITY and the autopilot has nothing new to check.
// Only enabled, unreferenced records received exclusively from feeds are
// removed; manual and legacy imports and disabled records are kept. A feed
// may send a removed candidate again; it is then checked afresh.
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
	expired, failed := feedPruneCandidates(snapshot, protected, now)
	ids := append(expired, failed...)
	if len(ids) == 0 {
		return 0, nil
	}
	if _, err := a.Nodes.DeleteBatch(ctx, ids, snapshot.Generation, now); err != nil {
		return 0, err
	}
	log.Printf("node catalogue: removed %d expired and %d failed feed candidates (%d of %d slots were used)", len(expired), len(failed), len(snapshot.Nodes), nodestore.MaxNodes)
	return len(ids), nil
}

// feedPruneCandidates lists unreferenced feed-only records that expired more
// than the grace period ago, and those whose latest check failed to connect
// to the node or to leave it, with no success on record.
func feedPruneCandidates(snapshot nodestore.Snapshot, protected map[string]string, now time.Time) (expired, failed []string) {
	kinds := map[string]string{}
	for _, s := range snapshot.Sources {
		kinds[s.ID] = s.Kind
	}
	for _, n := range snapshot.Nodes {
		if n.Disabled || len(n.Origins) == 0 || protected[n.ID] != "" {
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
		switch {
		case !feedOnly:
		case n.State == "expired" && stale:
			expired = append(expired, n.ID)
		case deadCandidate(n):
			failed = append(failed, n.ID)
		}
	}
	return expired, failed
}

// deadCandidate reports a node whose latest check could not connect to it,
// could not reach the internet through it, or whose configuration the proxy
// rejected. Such a node cannot carry any service; one success keeps it.
func deadCandidate(n nodestore.Node) bool {
	var latest nodestore.CheckRecord
	for _, c := range n.Health.History {
		if c.Verdict == "PASS" {
			return false
		}
		if c.CheckedAt.After(latest.CheckedAt) {
			latest = c
		}
	}
	if latest.Verdict != "ERROR" {
		return false
	}
	switch latest.ErrorCode {
	case "node-transport-failed", "node-egress-failed", "node-runtime-config-rejected":
		return true
	}
	return false
}
