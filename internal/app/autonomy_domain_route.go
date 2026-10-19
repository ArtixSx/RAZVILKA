package app

import (
	"context"

	"github.com/ArtixSx/razvilka/internal/autonomy"
	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/dataplane"
)

// A service with domains can be carried only by NFQWS2, which matches every
// connection by its own hostname. A VPN or proxy route (USQUE, WARP, AWG,
// WireGuard, Sing-box, Xray and their nodes) routes by IP: its DNS answers
// would capture unrelated sites sharing an address, and the plan refuses it
// with DOMAIN_FLOW_AUTHORITY_REQUIRED. The autopilot therefore never probes,
// reserves or applies such a route for this service. Trying it would only end
// in an Apply refusal repeated every round.
const autonomyStateDomainRouteUnavailable = "domain-route-unavailable"

func autonomyDomainService(service catalog.Service) bool { return len(service.Domains) != 0 }

// routeEligibleForService is the same predicate the plan uses for its blocker.
// CIDR-only services keep every route; readiness and proof are checked later.
func routeEligibleForService(service catalog.Service, route string) bool {
	return !autonomyDomainService(service) || dataplane.DomainFlowAuthority(route)
}

// finishAutonomyDomainService ends a round of a domain service after its own
// NFQWS2 options were tried. A healthy eligible route is kept (and follows a
// new device scope); anything else reports the typed reason without effects.
func (a *App) finishAutonomyDomainService(ctx context.Context, p autonomy.Policy, s autonomy.Service, r autonomy.Runtime, cfg config.Config, profile, current string, healthy bool) autonomy.Runtime {
	finish := func(state, message string) autonomy.Runtime { r.State, r.Message = state, message; return r }
	// Earlier node reserves can never be applied to this service.
	r.Reserves = nil
	if current != "" && !dataplane.DomainFlowAuthority(current) {
		return finish(autonomyStateDomainRouteUnavailable, "Применённый путь через VPN или прокси не подходит для сервиса с доменами: общий IP может принадлежать чужим сайтам. Автопилот его не обновляет и не заменяет. Выберите NFQWS2 или выключите сервис.")
	}
	if current != "" && healthy {
		if !sameNodeRecoveryStrings(cfg.AppliedServices[s.ID].Sources, s.Sources) {
			if err := a.applyAutonomyRoute(ctx, p, s, cfg, profile, current); err != nil {
				return finish("scope-pending", "Новая область устройств ещё не применена. Прежняя конфигурация сохранена.")
			}
			return finish("applied", "Проверенный путь применён к выбранным устройствам.")
		}
		return finish("healthy", "Работающий путь сохранён. Резерв через VPN или прокси для сервиса с доменами не подбирается.")
	}
	if current != "" {
		return finish(autonomyStateDomainRouteUnavailable, "Действующий путь не подтвердил работу сервиса. Сервис задан доменами, поэтому VPN и прокси не назначаются: общий IP может принадлежать чужим сайтам. Маршрут сохранён; проверка повторится.")
	}
	return finish(autonomyStateDomainRouteUnavailable, "Сервис задан доменами, поэтому подходит только NFQWS2: он проверяет имя сайта в каждом соединении. NFQWS2 не готов или не подтвердил сервис. VPN и прокси не назначаются: общий IP может принадлежать чужим сайтам.")
}
