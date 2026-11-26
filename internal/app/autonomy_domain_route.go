package app

import (
	"bytes"
	"context"
	"encoding/json"
	"slices"
	"time"

	"github.com/ArtixSx/razvilka/internal/autonomy"
	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/dataplane"
)

// A service with domains can be carried only by NFQWS2, which matches every
// connection by its own hostname. A VPN or proxy route (USQUE, WARP, AWG,
// WireGuard, Sing-box, Xray and their nodes) routes by IP: its DNS answers
// would capture unrelated sites sharing an address, and the plan refuses it
// with DOMAIN_FLOW_AUTHORITY_REQUIRED. An isolated Telegram Web check may
// retain a service-level reserve, but cannot select a client forwarding route.
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
		// Refresh only a domain list. An external mixed profile can already
		// carry a validated web request without a managed domain-list journal.
		if current == "nfqws2" {
			service, known := a.autonomyService(s.ID)
			if !known {
				return finish("removed", "Сервис удалён из каталога.")
			}
			if autonomyDefinition(service) != s.Definition || !a.autonomyConsent(p, s) || ctx.Err() != nil {
				return finish("paused", "Настройки сервиса изменились. Автопилот повторит проверку.")
			}
			if len(service.CIDRs) == 0 {
				return a.refreshAutonomyDomainNFQ(ctx, p, s, r, cfg, profile, service)
			}
			// A newly mixed definition must not inherit the success of the
			// old installed list merely because its HTTPS URL still answers.
			plan, _, err := a.Dataplane.Committed()
			if err != nil {
				return finish("requires-review", "Не удалось прочитать применённый список сервиса.")
			}
			for _, route := range plan.Routes {
				if route.ServiceID == s.ID && !nodeRecoveryServiceMatches(route, service) {
					return finish("capability-refused", "Для изменённого списка доменов и IP-сетей нужно подтвердить покрытие обоих типов. Прежний маршрут сохранён.")
				}
			}
		}
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

// An HTTPS result can stay positive when a second domain is added or removed.
// Compare the installed assignment with the owner's reviewed list before
// reporting it healthy or replacing it through the regular transaction.
func (a *App) refreshAutonomyDomainNFQ(ctx context.Context, p autonomy.Policy, s autonomy.Service, r autonomy.Runtime, cfg config.Config, profile string, service catalog.Service) autonomy.Runtime {
	finish := func(state, message string) autonomy.Runtime { r.State, r.Message = state, message; return r }
	plan, found, err := a.Dataplane.Committed()
	if err != nil || !found || plan.State != "committed" || plan.Revision != cfg.AppliedRevision ||
		plan.NetworkProfileID != "" && plan.NetworkProfileID != profile {
		return finish("requires-review", "Не удалось сопоставить действующий маршрут с журналом применения.")
	}
	applied := cfg.AppliedServices[s.ID]
	i := slices.IndexFunc(plan.Routes, func(route dataplane.Route) bool { return route.ServiceID == s.ID })
	if !applied.Enabled || i < 0 || plan.Routes[i].Resolved != "nfqws2" || !sameNodeRecoveryStrings(plan.Routes[i].Sources, applied.Sources) {
		return finish("requires-review", "В журнале отсутствует подтверждённое назначение NFQWS2 для этого сервиса и его устройств.")
	}
	if a.observeCommittedRuntime(ctx, plan) != nil {
		return finish("unconfirmed", "Сайт ответил, но работу применённой конфигурации подтвердить не удалось.")
	}
	route := plan.Routes[i]
	if nodeRecoveryServiceMatches(route, service) && sameNodeRecoveryStrings(applied.Sources, s.Sources) {
		return finish("healthy", "Проверены HTTPS сервиса, применённый список и работа NFQWS2.")
	}
	if s.ExpectedRoute == "auto" && !slices.Contains(p.PreferredRoutes, "nfqws2") {
		return finish("capability-refused", "NFQWS2 выключен в автоподборе. Обновление списка отложено.")
	}
	now := time.Now()
	if !r.ReserveSwitch(now, p.MaxSwitchesPerHour) {
		r.NextCheck = r.SwitchBudgetAt(now, p.MaxSwitchesPerHour)
		return finish("rate-limited", "Обновление доменного списка ожидает следующего разрешённого применения.")
	}
	r.State, r.Message = "applying", "Применяем подтверждённый состав доменного сервиса."
	if !a.autonomyRuntime(p.Revision, s.ID, r) {
		return finish("requires-review", "Не удалось сохранить начало применения.")
	}
	if err := a.applyAutonomyServiceRoute(ctx, p, s, cfg, profile, "nfqws2", false, &plan); err != nil {
		return finish(autonomyLegacyApplyRefused(err, &r, "Обновление доменного списка не подтверждено. Проверьте журнал применения."))
	}
	return finish("applied", "Подтверждённый доменный список применён к выбранным устройствам.")
}

func domainRefreshKeepsNeighbors(previous, next dataplane.Plan, serviceID string) bool {
	neighbors := func(plan dataplane.Plan) ([]byte, error) {
		routes := make([]dataplane.Route, 0, len(plan.Routes))
		for _, route := range plan.Routes {
			if route.ServiceID != serviceID {
				// AppliedRoute describes the plan *before* this one. Selected
				// and Resolved describe the retained assignment itself.
				route.AppliedRoute = ""
				routes = append(routes, route)
			}
		}
		// Empty optional selectors decode as nil after a journal round trip.
		return json.Marshal(routes)
	}
	before, oldErr := neighbors(previous)
	after, newErr := neighbors(next)
	return oldErr == nil && newErr == nil && bytes.Equal(before, after)
}
