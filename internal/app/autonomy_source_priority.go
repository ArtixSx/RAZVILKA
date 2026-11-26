package app

import (
	"context"
	"slices"
	"sort"
	"time"

	"github.com/ArtixSx/razvilka/internal/autonomy"
	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/nodestore"
)

// A preference is scheduling only. It never adds an origin to source consent
// or identifies a user-supplied subscription/key as an owned server.
func autonomySourceRank(p autonomy.Policy, node nodestore.Node, now time.Time) int {
	rank := len(p.PreferredSourceIDs)
	for _, origin := range node.Origins {
		if !allowedAutonomyOrigin(p, origin, now) {
			continue
		}
		if i := slices.Index(p.PreferredSourceIDs, origin.SourceID); i >= 0 && i < rank {
			rank = i
		}
	}
	return rank
}

// A deduplicated public/private profile is preferred only through its own
// separately permitted, fresh personal origin. The marker grants no consent.
func autonomyPersonalPriorities(p autonomy.Policy, snapshot nodestore.Snapshot, now time.Time) map[string]bool {
	personal := make(map[string]bool)
	for _, source := range snapshot.Sources {
		if source.PersonalProfile() && slices.Contains(p.SourceIDs, source.ID) {
			personal[source.ID] = true
		}
	}
	priority := make(map[string]bool)
	for _, node := range snapshot.Nodes {
		if node.PriorityCheck && allowedAutonomyNode(p, node, now) && slices.ContainsFunc(node.Origins, func(origin nodestore.Origin) bool {
			return personal[origin.SourceID] && allowedAutonomyOrigin(p, origin, now)
		}) {
			priority[node.ID] = true
		}
	}
	return priority
}

// Sort only the pending suffix, after existing fresh-proof ranking. Thus fresh
// hints cannot promote public peers ahead of an explicitly preferred source.
func (a *App) prioritizeAutonomySources(ctx context.Context, p autonomy.Policy, r *autonomy.Runtime, now time.Time, personal map[string]bool) (int, error) {
	if len(p.PreferredSourceIDs) == 0 && len(personal) == 0 {
		return 0, nil
	}
	ranks := map[string]int{}
	if len(p.PreferredSourceIDs) != 0 {
		snapshot, err := a.Nodes.Snapshot(ctx, now)
		if err != nil {
			return 0, err
		}
		for _, node := range snapshot.Nodes {
			ranks[node.ID] = autonomySourceRank(p, node, now)
		}
	}
	rank := func(id string) int {
		if personal[id] {
			return -1
		}
		if value, ok := ranks[id]; ok {
			return value
		}
		return len(p.PreferredSourceIDs)
	}
	pending := r.Search.Ordered[r.Search.Cursor:]
	sort.SliceStable(pending, func(i, j int) bool { return rank(pending[i]) < rank(pending[j]) })
	count := 0
	for _, id := range pending {
		if rank(id) == len(p.PreferredSourceIDs) {
			break
		}
		count++
	}
	return count, nil
}

func (a *App) tryAutonomyPreferredRoutes(ctx context.Context, p autonomy.Policy, s autonomy.Service, r autonomy.Runtime, cfg config.Config, service catalog.Service, profile string) (autonomy.Runtime, bool) {
	return a.tryAutonomyPreferredRoutesWithNFQWS2Review(ctx, p, s, r, cfg, service, profile, a.autonomyNFQWS2DomainOnlyProfile)
}

func (a *App) tryAutonomyPreferredRoutesWithNFQWS2Review(ctx context.Context, p autonomy.Policy, s autonomy.Service, r autonomy.Runtime, cfg config.Config, service catalog.Service, profile string, currentNFQWS2 func(context.Context) bool) (autonomy.Runtime, bool) {
	return a.tryAutonomyRoutePhase(ctx, p, s, r, cfg, service, profile, p.PreferredRoutes, 0, currentNFQWS2)
}

func (a *App) tryAutonomyRoutePhase(ctx context.Context, p autonomy.Policy, s autonomy.Service, r autonomy.Runtime, cfg config.Config, service catalog.Service, profile string, routes []string, probeTimeout time.Duration, currentNFQWS2 func(context.Context) bool) (autonomy.Runtime, bool) {
	finish := func(state, message string) (autonomy.Runtime, bool) {
		r.State, r.Message = state, message
		return r, true
	}
	for _, route := range routes {
		if ctx.Err() != nil {
			return finish("paused", "Подбор отменён.")
		}
		if !routeEligibleForService(service, route) {
			continue
		}
		if applied := cfg.AppliedServices[s.ID]; applied.Enabled && selectedRoute(applied) == route {
			continue
		}
		ready, installed := a.autonomyPreferredRouteAvailability(route)
		if route == "warp-wg" && !ready {
			if a.Warp != nil && !autonomyWARPRegistrationAllowed(p, a.Warp.Health().Policy) && !a.reusableAutonomyWARPProfile() {
				r.State, r.Message = "warp-consent-required", "Разрешите первую регистрацию WARP WireGuard в настройках автопилота."
				continue
			}
			if !installed {
				policy, permitted := a.autonomyInitialWARPPolicy(p, cfg, service)
				if !permitted {
					continue
				}
				owner, configs, dataplane := a.Warp, a.EngineConfigs, a.Dataplane
				state, message, retry := a.prepareAutonomyComponent(ctx, p, s, cfg, service, route, "WARP WireGuard", func(context.Context) bool {
					return a.Warp == owner && a.EngineConfigs == configs && a.Dataplane == dataplane &&
						dataplane.CanaryCapable(route) && owner.Health().Policy == policy
				})
				if state == "paused" {
					return finish(state, message)
				}
				if state != "" {
					r.State, r.Message = state, message
					if !retry.IsZero() {
						if len(p.SourceIDs) == 0 && len(p.PreferredRoutes) == 1 {
							r.NextCheck = retry
						} else {
							r.NextCheck = minTime(r.NextCheck, retry)
						}
						r.Message = autonomyComponentRetryMessage(message, retry, p.Timezone)
					}
					continue
				}
				ready, installed = a.autonomyPreferredRouteAvailability(route)
			}
			if !installed {
				continue
			}
			var done bool
			if !ready {
				r, done = a.tryAutonomyInitialWARP(ctx, p, s, r, cfg, service, profile)
				if done {
					return r, true
				}
			}
		}
		if route == "usque" {
			// Inventory readiness says nothing about an owned MASQUE session
			// or this service's canary. Use the same transaction for both a
			// saved session and first registration.
			var done bool
			r, done = a.tryAutonomyInitialUSQUE(ctx, p, s, r, cfg, service, profile, installed)
			if done {
				return r, true
			}
			continue
		}
		if !ready {
			continue
		}
		if route == "nfqws2" {
			if refusal := autonomyNFQWS2MixedRefusal(ctx, service, currentNFQWS2); refusal != nil {
				return autonomyCapabilityRefused(refusal, &r), true
			}
		}
		probeCtx, cancel := ctx, func() {}
		if probeTimeout > 0 {
			probeCtx, cancel = context.WithTimeout(ctx, probeTimeout)
		}
		observation := a.autonomyProbeRouteObservation(probeCtx, service, route, profile)
		cancel()
		if observation.pause(&r) {
			return r, true
		}
		if observation.Verdict != "PASS" {
			continue
		}
		if !r.ReserveSwitch(time.Now(), p.MaxSwitchesPerHour) {
			return finish("rate-limited", "Лимит применений исчерпан; проверенный обход пока не меняется.")
		}
		a.autonomyRuntime(p.Revision, s.ID, r)
		if err := a.applyAutonomyRoute(ctx, p, s, cfg, profile, route); err != nil {
			return finish(autonomyLegacyApplyRefused(err, &r, "Применение локального обхода не подтверждено; выполнена защита/откат."))
		}
		return finish("applied", "Подходящий обход применён через общую транзакцию.")
	}
	return r, false
}

func (a *App) autonomyPreferredRouteAvailability(route string) (ready, installed bool) {
	for _, option := range a.nodeRouteOptions() {
		if option.ID == route {
			ready, installed = option.Ready, option.Installed
		}
	}
	return ready, installed
}
