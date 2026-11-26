package app

import (
	"context"
	"errors"
	"reflect"
	"slices"
	"time"

	"github.com/ArtixSx/razvilka/internal/autonomy"
	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/usquediag"
)

func autonomyCommittedUSQUERoute(plan dataplane.Plan, cfg config.Config, s autonomy.Service, service catalog.Service, profile string) bool {
	if plan.State != "committed" || plan.Revision != cfg.AppliedRevision || plan.NetworkProfileID != profile || profile == "" ||
		plan.LAN != nil || cfg.NetworkPolicy != nil || cfg.AppliedNetworkPolicy != nil || !autonomyUSQUEService(service) {
		return false
	}
	state := cfg.AppliedServices[s.ID]
	if !state.Enabled || selectedRoute(state) != "usque" || !slices.Equal(state.Sources, s.Sources) || s.AllLAN != (len(state.Sources) == 0) {
		return false
	}
	routes := plan.RoutePlanFor("usque").Routes
	if len(routes) != 1 {
		return false
	}
	route := routes[0]
	frozen, err := dataplane.FrozenProbeService(route)
	return err == nil && route.ServiceID == s.ID && route.Selected == "usque" && route.Resolved == "usque" && route.NetworkPolicyRole == "" && len(route.SourceRefs) == 0 &&
		route.ProbeURL == service.ProbeURL && autonomyDefinition(frozen) == s.Definition && slices.Equal(route.CIDRs, service.CIDRs) && slices.Equal(route.Sources, state.Sources)
}

func (a *App) observeAutonomyCommittedUSQUE(ctx context.Context, p autonomy.Policy, s autonomy.Service, cfg config.Config, service catalog.Service, profile string, r *autonomy.Runtime) autonomyRouteObservation {
	unknown := func(reason string) autonomyRouteObservation {
		return autonomyRouteObservation{Verdict: "INCONCLUSIVE", Reason: reason}
	}
	manager, configs, store := a.Dataplane, a.EngineConfigs, a.Store
	files := a.SelfUpdateFiles
	if manager == nil || configs == nil || store == nil || files == nil || files.ControlRoot == "" || !slices.Contains(p.PreferredRoutes, "usque") {
		return unknown("masque-health-unavailable")
	}
	plan, exists, err := manager.Committed()
	if err != nil || !exists || !autonomyCommittedUSQUERoute(plan, cfg, s, service, profile) {
		return unknown("masque-committed-scope-changed")
	}
	if err := a.autonomyResourceGuard(ctx, p, s, cfg, service); err != nil {
		return unknown(autonomyObservationContextReason(ctx, "masque-resource-before", err))
	}
	owner, err := a.defaultConsentOwner(ctx)
	if err != nil {
		return unknown("masque-health-target-unavailable")
	}
	definitions := a.catalogSnapshot()
	definitionHash := applyReviewHash(definitions)
	custom, sources := a.CustomServices, a.Sources
	if sources != nil {
		ids := make([]string, 0, len(definitions.Services))
		for _, definition := range definitions.Services {
			ids = append(ids, definition.ID)
		}
		if !sources.AutomaticUseReady(ids) {
			return unknown("masque-health-target-unavailable")
		}
	}
	targets, err := owner.ReviewLegacyUSQUEProbeTargets(ctx, cfg, definitions, s.ID)
	if err != nil {
		return unknown("masque-health-target-unavailable")
	}
	checkCtx, err := usquediag.WithOwnedLegacyUSQUEProbeTargetReview(ctx, targets, s.ID, service.ProbeURL)
	if err != nil {
		return unknown("masque-health-target-unavailable")
	}
	controlRoot := files.ControlRoot
	control, err := a.Operations.ReviewControlEpoch(ctx, controlRoot)
	if err == nil {
		defer control.Close()
	} else {
		control = nil // An observation may still use the original target review.
	}
	guard := func(c context.Context) error {
		if c.Err() != nil {
			return c.Err()
		}
		if a.Dataplane != manager || a.EngineConfigs != configs || a.Store != store || a.CustomServices != custom || a.Sources != sources || a.SelfUpdateFiles != files || files.ControlRoot != controlRoot ||
			!a.autonomyConsent(p, s) || a.autonomyDiskCurrent(c) != nil || !reflect.DeepEqual(store.Get(), cfg) || a.autonomyRouteBlockReason(p, cfg) != "" ||
			applyReviewHash(a.catalogSnapshot()) != definitionHash {
			return dataplane.ErrReviewChanged
		}
		return nil
	}
	now := time.Now()
	canRestart := !r.SwitchBudgetAt(now, p.MaxSwitchesPerHour).After(now)
	result, err := manager.MonitorCommittedUSQUEHealth(dataplane.WithReviewGuard(checkCtx, guard), plan, configs, control, controlRoot, canRestart)
	if result.RestartAttempted {
		r.ReserveSwitch(time.Now(), p.MaxSwitchesPerHour)
	}
	if err != nil {
		switch {
		case errors.Is(err, dataplane.ErrOriginalProcessCleanup), errors.Is(err, dataplane.ErrExecutionJournal):
			a.Operations.FenceJournal()
			return unknown("masque-repair-cleanup-unconfirmed")
		case ctx.Err() != nil:
			return unknown("masque-check-canceled")
		case result.RetryAvailable:
			return unknown("masque-restart-retry")
		case errors.Is(err, dataplane.ErrUSQUEProviderUnconfirmed):
			return unknown("masque-provider-unconfirmed")
		case errors.Is(err, dataplane.ErrUSQUERestartBudget):
			r.NextCheck = r.SwitchBudgetAt(time.Now(), p.MaxSwitchesPerHour)
			return unknown("masque-restart-rate-limited")
		case errors.Is(err, dataplane.ErrUSQUELocalProcessUnconfirmed):
			return unknown("masque-local-unconfirmed")
		case result.RestartAttempted:
			return unknown("masque-repair-unconfirmed")
		default:
			return unknown(autonomyObservationContextReason(ctx, "masque-owned-health", err))
		}
	}
	if a.autonomyResourceGuard(ctx, p, s, cfg, service) != nil || guard(ctx) != nil {
		return unknown("masque-committed-scope-changed")
	}
	if result.Restarted {
		return autonomyRouteObservation{Verdict: "PASS", Reason: "masque-restarted"}
	}
	return autonomyRouteObservation{Verdict: "PASS"}
}
