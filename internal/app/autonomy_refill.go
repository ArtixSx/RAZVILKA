package app

import (
	"context"
	"time"

	"github.com/ArtixSx/razvilka/internal/autonomy"
	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/nodestore"
)

// Called with the worker's exclusive admission. Source enablement and persisted
// Retry-After are checked again by the single providerfeed worker before I/O.
func (a *App) autonomyRefill(ctx context.Context, p autonomy.Policy, s autonomy.Service, r autonomy.Runtime) {
	if ctx.Err() != nil || a.Operations.Snapshot().Fenced || a.NodeFeeds == nil || a.Store == nil || !a.autonomyConsent(p, s) {
		return
	}
	cfg := a.Store.Get()
	if cfg.SafeMode || cfg.ServiceControl.Stopped || cfg.ServiceControl.EffectiveMode() == "manual" || len(r.Reserves) >= p.ReserveTarget {
		return
	}
	service, ok := a.autonomyService(s.ID)
	if !ok || s.Removing || s.ExpectedRoute == "nfqws2" && catalog.IsNFQWS2Starter(service) {
		return
	}
	switch r.State {
	case "healthy", "applied", "searching", "unconfirmed", "origin-expired":
	default:
		return
	}
	// A poisoned exact checker cannot be repaired by downloading more URLs.
	if a.NodeChecker == nil || a.Nodes == nil {
		return
	}
	profile, err := a.freshNetworkProfile(ctx)
	if err != nil {
		return
	}
	// Candidates are checked a few per round. Fetching more while many wait
	// only fills the bounded catalogue with records nobody has checked.
	snapshot, err := a.Nodes.Snapshot(ctx, time.Now())
	if err != nil || uncheckedAutonomyCandidates(snapshot, p, s.ID, profile, time.Now()) >= autonomyRefillBacklog {
		return
	}
	useful, err := a.Nodes.SourceUtility(ctx, p.SourceIDs, p.Protocols, s.ID, profile, time.Now())
	if err != nil {
		return
	}
	decision, err := a.NodeFeeds.RequestRefillRanked(ctx, p.SourceIDs, useful)
	if err != nil {
		return
	}
	a.autonomy.mu.Lock()
	defer a.autonomy.mu.Unlock()
	if a.autonomy.doc.Policy.Revision != p.Revision {
		return
	}
	// Only bounded typed metadata, never endpoints or tokens.
	a.autonomy.refillState = decision
}

// Bind automatic IP refresh to immutable applied intent; passive catalogue
// imports never provide permission to replace selected credentials or servers.

// About half an hour of work at the default pace of two checks per round.
const autonomyRefillBacklog = 32

// uncheckedAutonomyCandidates counts permitted candidates without any check
// of this service in this network.
func uncheckedAutonomyCandidates(snapshot nodestore.Snapshot, p autonomy.Policy, serviceID, profile string, now time.Time) int {
	count := 0
	for _, n := range snapshot.Nodes {
		if !allowedAutonomyNode(p, n, now) {
			continue
		}
		checked := false
		for _, c := range n.Health.History {
			if c.ServiceID == serviceID && c.NetworkProfile == profile {
				checked = true
				break
			}
		}
		if !checked {
			count++
		}
	}
	return count
}
