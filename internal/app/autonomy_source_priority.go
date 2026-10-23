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
		if !slices.Contains(p.SourceIDs, origin.SourceID) || now.Before(origin.ReceivedAt) || !now.Before(origin.ExpiresAt) {
			continue
		}
		if i := slices.Index(p.PreferredSourceIDs, origin.SourceID); i >= 0 && i < rank {
			rank = i
		}
	}
	return rank
}

// Sort only the pending suffix, after existing fresh-proof ranking. Thus fresh
// hints cannot promote public peers ahead of an explicitly preferred source.
func (a *App) prioritizeAutonomySources(ctx context.Context, p autonomy.Policy, r *autonomy.Runtime, now time.Time) (int, error) {
	if len(p.PreferredSourceIDs) == 0 {
		return 0, nil
	}
	snapshot, err := a.Nodes.Snapshot(ctx, now)
	if err != nil {
		return 0, err
	}
	ranks := map[string]int{}
	for _, node := range snapshot.Nodes {
		ranks[node.ID] = autonomySourceRank(p, node, now)
	}
	rank := func(id string) int {
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
	finish := func(state, message string) (autonomy.Runtime, bool) {
		r.State, r.Message = state, message
		return r, true
	}
	for _, route := range p.PreferredRoutes {
		if ctx.Err() != nil {
			return finish("paused", "Подбор отменён.")
		}
		if !routeEligibleForService(service, route) {
			continue
		}
		ready := false
		for _, option := range a.nodeRouteOptions() {
			if option.ID == route && option.Ready {
				ready = true
			}
		}
		if !ready {
			continue
		}
		if route == "nfqws2" {
			if refusal := autonomyNFQWS2MixedRefusal(ctx, service, currentNFQWS2); refusal != nil {
				return autonomyCapabilityRefused(refusal, &r), true
			}
		}
		observation := a.autonomyProbeRouteObservation(ctx, service, route, profile)
		if observation.pause(&r) {
			return r, true
		}
		if observation.Verdict != "PASS" {
			continue
		}
		if !r.ReserveSwitch(time.Now(), p.MaxSwitchesPerHour) {
			return finish("rate-limited", "Лимит применений исчерпан; проверенный обход пока не меняется.")
		}
		a.autonomyRuntime(s.ID, r)
		if err := a.applyAutonomyRoute(ctx, p, s, cfg, profile, route); err != nil {
			return finish(autonomyLegacyApplyRefused(err, &r, "Применение локального обхода не подтверждено; выполнена защита/откат."))
		}
		return finish("applied", "Подходящий обход применён через общую транзакцию.")
	}
	return r, false
}
