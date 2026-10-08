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
	store := a.Store
	cfg := store.Get()
	if cfg.SafeMode || cfg.ServiceControl.Stopped || cfg.ServiceControl.EffectiveMode() == "manual" || len(r.Reserves) >= p.ReserveTarget {
		return
	}
	service, ok := a.autonomyService(s.ID)
	if !ok || s.Removing || s.ExpectedRoute == "nfqws2" && catalog.IsNFQWS2Starter(service) {
		return
	}
	if a.autonomyResourceGuard(ctx, p, s, cfg, service) != nil {
		return
	}
	switch r.State {
	case "healthy", "applied", "searching", "unconfirmed", "origin-expired":
	default:
		return
	}
	// A poisoned exact checker cannot be repaired by downloading more URLs.
	if a.Nodes == nil {
		return
	}
	engine := autonomyNodeEngine(s.ExpectedRoute)
	if _, err := a.nodeCheckerForEngine(engine); err != nil {
		return
	}
	if a.autonomyDiskCurrent(ctx) != nil {
		return
	}
	profile, err := a.freshNetworkProfile(ctx)
	if err != nil {
		return
	}
	// Candidates are checked a few per round. Fetching more while many wait
	// only fills the bounded catalogue with records nobody has checked.
	snapshot, err := a.Nodes.Snapshot(ctx, time.Now())
	if err != nil {
		return
	}
	if r.Search != nil && r.Search.Version == autonomyTraversalVersion(p, s, engine, profile) && !r.Search.Exhausted {
		// Finish the bounded snapshot before requesting its next passive page.
		return
	}
	if uncheckedAutonomySearchCandidates(snapshot, p, s, r, engine, profile, time.Now()) >= autonomyRefillBacklog {
		return
	}
	useful, err := a.Nodes.SourceUtilityForEngine(ctx, engine, p.SourceIDs, p.Protocols, s.ID, profile, time.Now())
	if err != nil {
		return
	}
	if a.Store != store || !a.autonomyConsent(p, s) || a.autonomyDiskCurrent(ctx) != nil {
		return
	}
	if a.autonomyResourceGuard(ctx, p, s, cfg, service) != nil {
		return
	}
	decision, err := a.NodeFeeds.RequestRefillRanked(ctx, p.SourceIDs, useful)
	if err != nil {
		return
	}
	if a.Store != store || a.autonomyResourceGuard(ctx, p, s, cfg, service) != nil {
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

// Unsupported checks deliberately have no history. Only a matching durable
// traversal may count their consumed entries, and only for refill scheduling.
func uncheckedAutonomySearchCandidates(snapshot nodestore.Snapshot, p autonomy.Policy, s autonomy.Service, r autonomy.Runtime, engine, profile string, now time.Time) int {
	consumed := map[string]bool{}
	if r.Search != nil && r.Search.Version == autonomyTraversalVersion(p, s, engine, profile) {
		for _, id := range r.Search.Ordered[:r.Search.Cursor] {
			consumed[id] = true
		}
	}
	count := 0
	for _, n := range snapshot.Nodes {
		if !allowedAutonomyNode(p, n, now) || consumed[n.ID] {
			continue
		}
		checked := false
		for _, c := range n.Health.History {
			if c.ServiceID == s.ID && c.NetworkProfile == profile && c.RoutePathID == engine+":"+n.ID {
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
