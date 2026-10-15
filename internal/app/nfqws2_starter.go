package app

import (
	"context"
	"fmt"
	"math"
	"reflect"
	"time"

	"github.com/ArtixSx/razvilka/internal/autonomy"
	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/onboarding"
)

// Called only after runAutonomyService has checked consent, definition, draft,
// journal and current network. A first-setup starter is explicitly NFQWS2-only:
// no silent VLESS/USQUE/WARP fallback and no requirement to import proxy keys.
func (a *App) runNFQWS2Starter(ctx context.Context, p autonomy.Policy, s autonomy.Service, r autonomy.Runtime, service catalog.Service, cfg config.Config, profile string) autonomy.Runtime {
	finish := func(state, message string) autonomy.Runtime { r.State, r.Message = state, message; return r }
	applied := cfg.AppliedServices[s.ID]
	// The owner's draft may already return the service to NFQWS2 while another
	// route is still applied (for example, a node whose subscription expired).
	// That draft is the owner's choice, so the stale route is replaced below.
	returning := applied.Enabled && selectedRoute(applied) != "nfqws2"
	if returning && !nfqws2StandardDraft(service, s, cfg.Services[s.ID]) {
		return finish("manual-change", "У сервиса уже назначен другой маршрут. Базовый набор его не заменяет.")
	}
	if !a.nfqws2RouteReady() {
		return finish("component-unavailable", "Назначен NFQWS2, но компонент ещё не готов. Другой обход автоматически не назначается.")
	}
	if at := r.SwitchBudgetAt(time.Now(), p.MaxSwitchesPerHour); !returning && !applied.Enabled && at.After(time.Now()) {
		// Only an apply needs the budget, and a check without one cannot lead
		// to it. Each check takes a whole round (up to 90 s), so waiting here
		// leaves the rounds to the other services.
		r.NextCheck = at
		return finish("rate-limited", fmt.Sprintf("Лимит применений за час исчерпан. Следующая попытка примерно через %d мин.", max(1, int(math.Ceil(time.Until(at).Minutes())))))
	}
	if !returning && !a.nfqws2RouteRunning() {
		// The isolated check sends one request through the running daemon's
		// queue. A stopped daemon can never confirm it, so say why.
		return finish("component-stopped", "NFQWS2 установлен, но не запущен, поэтому сервис нельзя проверить. Запустите NFQWS2; автопилот проверит сервис в следующем раунде. Другой обход автоматически не назначается.")
	}
	observation := a.autonomyProbeRouteObservation(ctx, service, "nfqws2", profile)
	if observation.pause(&r) {
		return r
	}
	verdict := observation.Verdict
	r.CheckedAt = time.Now().UTC()
	r.Observe("nfqws2", profile, verdict, time.Now(), time.Duration(p.FailureConfirmSeconds)*time.Second)
	r.Reserves = nil
	if verdict != "PASS" && !returning {
		return finish("unconfirmed", "Проверка через NFQWS2 не подтвердила веб-сценарий. Назначение сохранено; проверка повторится без смены обхода.")
	}
	if ctx.Err() != nil || !a.autonomyConsent(p, s) || !reflect.DeepEqual(a.Store.Get(), cfg) {
		return finish("paused", "Проверка отменена или изменились настройки. Сеть не изменена.")
	}
	outdated := false
	if !returning && applied.Enabled && sameNodeRecoveryStrings(applied.Sources, s.Sources) {
		if plan, exists, err := a.Dataplane.Committed(); err == nil && exists && plan.State == "committed" && plan.Revision == cfg.AppliedRevision && a.Dataplane.ObserveCommittedRuntime(ctx, plan) == nil {
			// A RAZVILKA update may extend the reviewed list: apply NFQWS2
			// again so the new domains reach its list, then report healthy.
			if outdated = !committedServiceCurrent(plan, service); !outdated {
				return finish("healthy", "Веб-сценарий и действующий NFQWS2 подтверждены. Штатное назначение сохранено.")
			}
		}
	}
	if !r.ReserveSwitch(time.Now(), p.MaxSwitchesPerHour) {
		return finish("rate-limited", "Достигнут лимит применений. Назначение NFQWS2 сохранено до следующей попытки.")
	}
	r.State, r.Message = "applying", "Проверен NFQWS2. Применяем только этот сервис и выбранные устройства."
	if returning {
		r.Message = "Применяем ваш возврат сервиса на штатный NFQWS2."
	} else if outdated {
		r.Message = "Состав сервиса обновился. Применяем NFQWS2 к новому составу."
	}
	a.autonomyRuntime(s.ID, r)
	if err := a.applyAutonomyRoute(ctx, p, s, cfg, profile, "nfqws2"); err != nil {
		if state, message, blocked := autonomyRouteDependency(err, &r); blocked {
			return finish(state, message)
		}
		return finish("apply-refused", "NFQWS2 не удалось подтвердить после применения. Использована штатная защита и откат.")
	}
	if returning {
		if verdict != "PASS" {
			return finish("applied", "Ваш возврат на штатный NFQWS2 применён. Веб-проверка через NFQWS2 пока не подтверждена; назначение сохранено.")
		}
		return finish("applied", "Ваш возврат на штатный NFQWS2 применён и проверен.")
	}
	if outdated {
		return finish("applied", "Состав сервиса обновился: NFQWS2 применён к новому составу.")
	}
	return finish("applied", "NFQWS2 применён через общую транзакцию. Проверка остальных функций сервиса выполняется отдельно.")
}

// Snapshot only the fields needed to avoid taking over existing routes. The
// whole configuration revision fences additional reviewed profile bindings.
func starterConfigView(cfg config.Config) onboarding.ConfigView {
	v := onboarding.ConfigView{Revision: cfg.Revision, Services: map[string]onboarding.State{}, AppliedServices: map[string]onboarding.State{}, ServicePolicies: map[string]bool{}}
	for id, s := range cfg.Services {
		v.Services[id] = starterServiceState(s)
	}
	for id, s := range cfg.AppliedServices {
		v.AppliedServices[id] = starterServiceState(s)
	}
	for id := range cfg.ServicePolicies {
		v.ServicePolicies[id] = true
	}
	v.ServiceControl.SuspendedServices = map[string]onboarding.State{}
	for id, s := range cfg.ServiceControl.SuspendedServices {
		v.ServiceControl.SuspendedServices[id] = starterServiceState(s)
	}
	v.ServiceControl.SuspendedRoutes = cfg.ServiceControl.SuspendedRoutes
	return v
}

func starterServiceState(s config.ServiceState) onboarding.State {
	return onboarding.State{Enabled: s.Enabled, Mode: s.Mode, Route: s.Route, Sources: append([]string(nil), s.Sources...)}
}
