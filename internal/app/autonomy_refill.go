package app

import (
	"context"
	"github.com/ArtixSx/razvilka/internal/autonomy"
	"github.com/ArtixSx/razvilka/internal/catalog"
)

// Called with the worker's exclusive admission. Source enablement and persisted
// Retry-After are checked again by the single providerfeed worker before I/O.
func (a *App) autonomyRefill(ctx context.Context, p autonomy.Policy, s autonomy.Service, r autonomy.Runtime) {
	if ctx.Err() != nil || a.NodeFeeds == nil || a.Store == nil || !a.autonomyConsent(p, s) {
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
	if a.NodeChecker == nil {
		return
	}
	decision, err := a.NodeFeeds.RequestRefill(ctx, p.SourceIDs)
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
