package app

import (
	"context"
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
	if applied.Enabled && selectedRoute(applied) != "nfqws2" {
		return finish("manual-change", "У сервиса уже назначен другой маршрут. Базовый набор его не заменяет.")
	}
	ready := false
	for _, o := range a.nodeRouteOptions() {
		if o.ID == "nfqws2" && o.Ready {
			ready = true
			break
		}
	}
	if !ready {
		return finish("component-unavailable", "Назначен NFQWS2, но компонент ещё не готов. Другой обход автоматически не назначается.")
	}
	verdict := a.autonomyProbeRoute(ctx, service, "nfqws2", profile)
	r.CheckedAt = time.Now().UTC()
	r.Observe("nfqws2", profile, verdict, time.Now(), time.Duration(p.FailureConfirmSeconds)*time.Second)
	r.Reserves = nil
	if verdict != "PASS" {
		return finish("unconfirmed", "Проверка через NFQWS2 не подтвердила веб-сценарий. Назначение сохранено; проверка повторится без смены обхода.")
	}
	if ctx.Err() != nil || !a.autonomyConsent(p, s) || !reflect.DeepEqual(a.Store.Get(), cfg) {
		return finish("paused", "Проверка отменена или изменились настройки. Сеть не изменена.")
	}
	if applied.Enabled && sameNodeRecoveryStrings(applied.Sources, s.Sources) {
		if plan, exists, err := a.Dataplane.Committed(); err == nil && exists && plan.State == "committed" && plan.Revision == cfg.AppliedRevision && a.Dataplane.ObserveCommittedRuntime(ctx, plan) == nil {
			return finish("healthy", "Веб-сценарий и действующий NFQWS2 подтверждены. Штатное назначение сохранено.")
		}
	}
	if !r.ReserveSwitch(time.Now(), p.MaxSwitchesPerHour) {
		return finish("rate-limited", "Достигнут лимит применений. Назначение NFQWS2 сохранено до следующей попытки.")
	}
	r.State, r.Message = "applying", "Проверен NFQWS2. Применяем только этот сервис и выбранные устройства."
	a.autonomyRuntime(s.ID, r)
	if err := a.applyAutonomyRoute(ctx, p, s, cfg, profile, "nfqws2"); err != nil {
		return finish("apply-refused", "NFQWS2 не удалось подтвердить после применения. Использована штатная защита и откат.")
	}
	return finish("applied", "NFQWS2 применён через общую транзакцию. Проверка остальных функций сервиса выполняется отдельно.")
}

// Snapshot only the state needed to avoid taking over existing routes. Draft
// fingerprints retain the config.ServiceState serialization exactly.
func starterConfigView(cfg config.Config) onboarding.ConfigView {
	v := onboarding.ConfigView{Revision: cfg.Revision, Services: map[string]onboarding.State{}, AppliedServices: map[string]onboarding.State{}, ServicePolicies: map[string]bool{}}
	for id, s := range cfg.Services {
		v.Services[id] = onboarding.State(s)
	}
	for id, s := range cfg.AppliedServices {
		v.AppliedServices[id] = onboarding.State(s)
	}
	for id := range cfg.ServicePolicies {
		v.ServicePolicies[id] = true
	}
	v.ServiceControl.SuspendedServices = map[string]onboarding.State{}
	for id, s := range cfg.ServiceControl.SuspendedServices {
		v.ServiceControl.SuspendedServices[id] = onboarding.State(s)
	}
	v.ServiceControl.SuspendedRoutes = cfg.ServiceControl.SuspendedRoutes
	return v
}
