package app

import (
	"context"
	"slices"

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
		return finish(autonomyStateDomainRouteUnavailable, "Применённый путь через VPN или прокси не подходит для сервиса с доменами: общий IP может принадлежать чужим сайтам. Автопилот его не обновляет и не заменяет. Требуется просмотр состава сервиса и поддерживаемого профиля.")
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
	// These observations explain the result only. A ready component is not
	// proof of coverage for the service's selectors or selected devices, and an
	// unknown/external profile must not be declared a closed first-start profile.
	installed, running, ready := false, false, false
	for _, option := range a.nodeRouteOptions() {
		if option.ID == "nfqws2" {
			installed = installed || option.Installed
			running = running || option.Running
			ready = ready || option.Ready
		}
	}
	stopped := ""
	if installed && !running {
		stopped = "NFQWS2 установлен, но не запущен. "
	}
	limits := ""
	if service, ok := a.autonomyService(s.ID); ok && len(service.Domains) != 0 && len(service.CIDRs) != 0 {
		limits = "Домены и IP-сети: работа полного списка не подтверждена. Для закрытого профиля NFQWS2 доступны только домены/TCP 443 для всей LAN. "
	}
	if !s.AllLAN || len(s.Sources) != 0 {
		if limits == "" {
			limits = "Для закрытого профиля NFQWS2 поддерживается вся домашняя сеть. "
		}
		limits += "Работа текущего профиля для выбранных устройств не подтверждена. "
	}
	if limits != "" {
		return finish(autonomyStateDomainRouteUnavailable, stopped+limits+"Список и область сохранены.")
	}
	// Name the prerequisite that the owner can actually change. Importing more
	// nodes or selecting a DNS profile does not produce a domain-flow runtime,
	// and must not be presented as a repair for this list-mode restriction.
	const boundary = " Для доменного списка VPN и прокси недоступны; импорт подключений и смена DNS не помогут. Для них нужен отдельный сервис с проверенными IP-сетями."
	if !slices.Contains(p.PreferredRoutes, "nfqws2") {
		return finish(autonomyStateDomainRouteUnavailable, "Разрешите NFQWS2 в маршрутах автопилота и выполните «Проверка NFQWS2» для доменного сервиса."+boundary)
	}
	if stopped != "" {
		return finish(autonomyStateDomainRouteUnavailable, stopped+"Без работающего процесса «Проверка NFQWS2» не подтвердит сервис. Запустите NFQWS2 и повторите проверку. Маршрут сохранён.")
	}
	if !ready {
		return finish(autonomyStateDomainRouteUnavailable, "NFQWS2 не готов. Откройте «Обходы», настройте NFQWS2 и выполните «Проверка NFQWS2» для сервиса."+boundary)
	}
	return finish(autonomyStateDomainRouteUnavailable, "Результат «Проверка NFQWS2» не подтвердил доступ к сервису."+boundary)
}
