package app

import (
	"context"
	"reflect"
	"time"

	"github.com/ArtixSx/razvilka/internal/auditlog"
	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/dataplane"
)

// Reuse the existing recovery schedule and admission gate. A router firewall
// rebuild may erase a whole owned chain without changing the WAN fingerprint.
// Restoring that chain preserves the applied intent; it never consumes drafts,
// chooses another endpoint or starts a component.
func (a *App) restoreForwardingRound(ctx context.Context) error {
	if a.Dataplane == nil {
		return nil
	}
	return a.restoreAppliedForwarding(ctx, a.Dataplane.RestoreCommittedForwarding)
}

func (a *App) restoreAppliedForwarding(ctx context.Context, restore func(context.Context, dataplane.Plan) (map[string]bool, error)) error {
	if a.Store == nil || a.Dataplane == nil || restore == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	release, err := a.Operations.Exclusive(ctx)
	if err != nil {
		return err // A user operation wins; the next scheduled round retries.
	}
	defer release()
	cfg := a.Store.Get()
	if cfg.SafeMode || cfg.ServiceControl.Stopped {
		return nil
	}
	plan, exists, err := a.Dataplane.Committed()
	if err != nil || !exists {
		return err
	}
	if plan.Revision != cfg.AppliedRevision || plan.SafeMode || plan.State != "committed" || !appliedForwardingMatchesPlan(cfg, plan) {
		return dataplane.ErrReviewChanged
	}
	guard := func(ctx context.Context) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		current := a.Store.Get()
		if current.SafeMode || current.ServiceControl.Stopped || current.AppliedRevision != cfg.AppliedRevision || !reflect.DeepEqual(current.AppliedServices, cfg.AppliedServices) {
			return dataplane.ErrReviewChanged
		}
		return nil
	}
	started := time.Now()
	changed, err := restore(dataplane.WithReviewGuard(ctx, guard), plan)
	if err != nil {
		return err
	}
	for _, repaired := range changed {
		if repaired && a.Audit != nil {
			_ = a.Audit.Append(auditlog.Event{Action: "RESTORE", Path: "/runtime/forwarding", Outcome: "ok", Actor: "router", RemoteIP: "local", DurationMS: time.Since(started).Milliseconds()})
			break
		}
	}
	return nil
}

func appliedForwardingMatchesPlan(cfg config.Config, plan dataplane.Plan) bool {
	seen := make(map[string]bool, len(plan.Routes))
	for _, route := range plan.Routes {
		service, exists := cfg.AppliedServices[route.ServiceID]
		if !exists || !service.Enabled || seen[route.ServiceID] || selectedRoute(service) != route.Selected || !sameNodeRecoveryStrings(service.Sources, route.Sources) {
			return false
		}
		seen[route.ServiceID] = true
	}
	for id, service := range cfg.AppliedServices {
		if service.Enabled && !seen[id] {
			return false
		}
	}
	return len(seen) > 0
}
