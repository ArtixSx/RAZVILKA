package app

import (
	"context"
	"errors"
	"slices"
	"time"

	"github.com/ArtixSx/razvilka/internal/autonomy"
	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/components"
	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/engine"
	routecatalog "github.com/ArtixSx/razvilka/internal/routes"
)

const autonomyInstallRetry = 15 * time.Minute

func (a *App) autonomyNodeEngineInstalled(id string) bool {
	if id == components.MASQUESidecarComponent {
		return dataplane.DiscoverHost().MASQUESingBox
	}
	if a.nodeReviews.options != nil {
		for _, option := range a.nodeReviews.options() {
			if option.ID == id && option.Installed {
				return true
			}
		}
		return false
	}
	return (engine.Detector{}).Installed(id)
}

// The caller holds the round owner's admission and has confirmed the service's
// policy and device scope. Component preparation grants no route authority.
func (a *App) prepareAutonomyComponent(ctx context.Context, p autonomy.Policy, s autonomy.Service, cfg config.Config, service catalog.Service, id, name string, authorize func(context.Context) bool) (state, message string, retryAt time.Time) {
	route := id
	privateSidecar := id == components.MASQUESidecarComponent
	if privateSidecar {
		route = "usque"
		if authorize == nil {
			return "component-unavailable", "Для подготовки Sing-box для MASQUE требуется проверка выбранного сервиса.", time.Time{}
		}
	}
	if a.autonomyNodeEngineInstalled(id) {
		return "", "", time.Time{}
	}
	if !slices.Contains(p.PreferredRoutes, route) || authorize != nil && !authorize(ctx) {
		return "component-unavailable", "Для проверки нет разрешённого совместимого движка.", time.Time{}
	}
	if a.Components == nil {
		return "component-unavailable", name + " отсутствует. Штатный установщик компонентов недоступен.", time.Time{}
	}
	if id != "usque" && !privateSidecar && a.Components.Opkg == "" {
		return "component-unavailable", name + " отсутствует. Штатный установщик Entware недоступен.", time.Time{}
	}
	legacySchedule := p.InstallMissingComponents == nil
	if legacySchedule && p.Components.Mode != "install" || !legacySchedule && !*p.InstallMissingComponents {
		return "component-unavailable", name + " отсутствует. Автоматическая установка недостающих компонентов не разрешена.", time.Time{}
	}
	now := time.Now()
	var slot string
	if legacySchedule {
		var open bool
		slot, open = autonomy.WindowKey(p.Components, p.Timezone, now)
		if !open {
			return "component-window", name + " отсутствует. Сохранённая политика допускает установку только в выбранном окне.", autonomy.NextWindow(p.Components, p.Timezone, now)
		}
	}
	store, manager := a.Store, a.Components
	guard := func(c context.Context) error {
		if err := c.Err(); err != nil {
			return err
		}
		if store == nil || a.Store != store || a.Components != manager || !a.autonomyConsent(p, s) || a.autonomyDiskCurrent(c) != nil || authorize != nil && !authorize(c) {
			return dataplane.ErrReviewChanged
		}
		if legacySchedule {
			currentSlot, open := autonomy.WindowKey(p.Components, p.Timezone, time.Now())
			if !open || currentSlot != slot {
				return dataplane.ErrReviewChanged
			}
		}
		current := store.Get()
		if current.Revision != cfg.Revision || a.autonomyRouteBlockReason(p, current) != "" {
			return dataplane.ErrReviewChanged
		}
		// WARP and an ordinary WireGuard route share this Entware package.
		if id == "warp-wg" && a.componentRuntimeBlocker("wireguard", "install") != nil {
			return components.ErrRecoveryAuthority
		}
		return a.autonomyResourceGuard(c, p, s, cfg, service)
	}
	if err := guard(ctx); err != nil {
		return "paused", "Подготовка движка отменена: настройки или область изменились.", time.Time{}
	}
	last, err := manager.LastInstallAttempt(id)
	if err != nil {
		return "component-unavailable", name + " отсутствует. Не удалось проверить журнал установщика.", time.Time{}
	}
	if due := last.Add(autonomyInstallRetry); now.Before(due) {
		return "component-retry", name + " отсутствует. Следующая попытка установки запланирована.", autonomyComponentRetryAt(p, due)
	}

	installCtx, cancel := context.WithTimeout(ctx, 100*time.Second)
	defer cancel()
	if err := manager.RecordOperation(id, "install", "running", "Автопилот: подготовка отсутствующего компонента"); err != nil {
		return "component-unavailable", name + " отсутствует. Не удалось сохранить попытку установки.", time.Time{}
	}
	err = a.installAutonomyComponent(installCtx, id, manager, guard)
	if err == nil && !a.autonomyNodeEngineInstalled(id) {
		err = dataplane.ErrExactNodeUnavailable
	}
	if (id == "usque" || privateSidecar) && errors.Is(err, components.ErrUSQUEInstallPending) {
		_ = manager.RecordOperation(id, "install", "running", "Сохранение исполняемого файла требует проверки штатного установщика")
		return "masque-publication-unconfirmed", "Не подтверждено сохранение компонента " + name + ". Автопилот повторит проверку файла.", time.Now().Add(autonomyInstallRetry)
	}
	if id == "nfqws2" && errors.Is(err, components.ErrUpdatePending) {
		_ = manager.RecordOperation(id, "install", "running", "Первая установка NFQWS2 требует проверки сохранённого журнала")
		return "requires-review", "Первая установка NFQWS2 требует проверки журнала. Повтор установки приостановлен.", time.Time{}
	}
	if err != nil {
		_ = manager.RecordOperation(id, "install", "failed", "Автопилот: пакет или рабочий файл компонента не подтверждён")
		if guard(ctx) != nil {
			return "paused", "Подготовка движка прервана: условия установки изменились.", time.Time{}
		}
		if privateSidecar {
			switch {
			case errors.Is(err, components.ErrComponentAlreadyInstalled):
				// The actual adapter will independently review the available path.
				return "", "", time.Time{}
			case errors.Is(err, components.ErrMASQUESidecarUnsupported):
				return "component-unavailable", "Для этой платформы или установки нет проверенного компонента Sing-box для MASQUE.", time.Time{}
			case errors.Is(err, components.ErrMASQUESidecarIntegrity):
				return "component-retry", "Sing-box для MASQUE не прошёл проверку файла. Повторная попытка запланирована.", autonomyComponentRetryAt(p, time.Now().Add(autonomyInstallRetry))
			}
		}
		if id == "usque" {
			switch {
			case errors.Is(err, components.ErrComponentAlreadyInstalled):
				// An executable appeared during the attempt. The MASQUE source
				// review must still prove its exact origin before it can be used.
				return "", "", time.Time{}
			case errors.Is(err, components.ErrUSQUEVendorOwner):
				return "component-unavailable", "Движок USQUE принадлежит другому сетевому исполнителю. Автопилот сохраняет его настройки.", time.Time{}
			case errors.Is(err, components.ErrUSQUEInstallUnsupported):
				return "component-unavailable", "Штатная подготовка USQUE недоступна на этой платформе или в этой установке.", time.Time{}
			}
		}
		return "component-retry", name + " не подготовлен. Повторная попытка запланирована. Подробности доступны в журнале установки.", autonomyComponentRetryAt(p, time.Now().Add(autonomyInstallRetry))
	}
	_ = manager.RecordOperation(id, "install", "succeeded", "Автопилот: установка и исполняемый файл компонента подтверждены")
	if guard(ctx) != nil {
		return "paused", "Движок установлен. Перед подключением автопилот заново проверит настройки и область.", time.Time{}
	}
	return "", "", time.Time{}
}

func autonomyComponentRetryAt(p autonomy.Policy, due time.Time) time.Time {
	if p.InstallMissingComponents != nil {
		return due
	}
	next := autonomy.NextWindow(p.Components, p.Timezone, due)
	if !next.IsZero() && next.Before(due) {
		return due
	}
	return next
}

func autonomyComponentRetryMessage(message string, retry time.Time, timezone string) string {
	if zone, err := time.LoadLocation(timezone); err == nil {
		retry = retry.In(zone)
	}
	return message + " Следующая попытка установки " + retry.Format("02.01.2006 в 15:04 MST") + "."
}

func autonomyWaitingForComponent(r autonomy.Runtime) bool {
	return r.State == "component-window" || r.State == "component-retry" || r.State == "component-unavailable"
}

func (a *App) installAutonomyComponent(ctx context.Context, id string, manager *components.Manager, guard func(context.Context) error) error {
	if id == components.MASQUESidecarComponent {
		dataplaneManager, configs := a.Dataplane, a.EngineConfigs
		if dataplaneManager == nil || !dataplaneManager.USQUEMissingManagedSidecar(configs) {
			return components.ErrRecoveryAuthority
		}
		_, err := manager.InstallInitialMASQUESidecar(ctx, guard, func(c context.Context, publish func() error) error {
			if a.Dataplane != dataplaneManager || a.EngineConfigs != configs {
				return dataplane.ErrReviewChanged
			}
			return dataplaneManager.PublishInitialUSQUECompanion(c, configs, publish)
		})
		return err
	}
	if id == "usque" {
		_, err := manager.InstallInitialUSQUE(ctx, guard)
		return err
	}
	if id == "nfqws2" {
		// Its installer has a pinned package source and reviews actual
		// dependencies, ownership and package state itself.
		if err := a.nfqwsPackageMutationGuard(id); err != nil {
			return err
		}
		if a.componentRuntimeBlocker(id, "install") != nil {
			return components.ErrRecoveryAuthority
		}
		_, err := a.installInitialNFQWS(ctx, guard)
		return err
	}
	plan, err := manager.Plan(ctx, id, "install", false)
	if err != nil {
		return err
	}
	a.enrichComponentPlan(&plan)
	if !plan.Ready && installCatalogRefreshNeeded(plan) {
		if err := manager.RefreshInstallCatalog(ctx, guard); err != nil {
			return err
		}
		plan, err = manager.Plan(ctx, id, "install", false)
		if err != nil {
			return err
		}
		a.enrichComponentPlan(&plan)
	}
	if !plan.Ready || a.componentRuntimeBlocker(id, "install") != nil {
		return components.ErrRecoveryAuthority
	}
	_, err = manager.InstallAbsent(ctx, id, guard)
	return err
}

func installCatalogRefreshNeeded(plan components.Plan) bool {
	if len(plan.Blockers) == 0 {
		return false
	}
	for _, blocker := range plan.Blockers {
		switch blocker.Code {
		case "CATALOG_STALE", "NOT_AVAILABLE", "DEPENDENCY_UNAVAILABLE":
		default:
			return false
		}
	}
	return true
}

// Show prerequisites only for a method eligible for this service. A closed
// route is not made eligible by a local config file or a successful enrollment.
func (a *App) autonomyMissingTunnelPrerequisite(p autonomy.Policy, cfg config.Config, service catalog.Service) string {
	var options []routecatalog.Option
	for _, id := range p.PreferredRoutes {
		if !slices.Contains([]string{"warp-wg", "usque", "wireguard", "amneziawg"}, id) ||
			!routeEligibleForService(service, id) || a.autonomyCapabilityRefusal(cfg, service.ID, id) != nil {
			continue
		}
		if options == nil {
			options = a.nodeRouteOptions()
		}
		for _, option := range options {
			if option.ID != id || option.Ready {
				continue
			}
			staged := false
			if option.Installed && (id == "warp-wg" || id == "usque") && a.EngineConfigs != nil {
				content, err := a.EngineConfigs.ReadExpert(id, "main")
				staged = err == nil && content.Source == "staged"
			}
			return autonomyTunnelPrerequisite(option, staged)
		}
	}
	return ""
}

func autonomyTunnelPrerequisite(option routecatalog.Option, staged bool) string {
	name, profile := "", "профиль удалённого peer"
	switch option.ID {
	case "warp-wg":
		name, profile = "WARP WireGuard", "профиль WARP"
	case "usque":
		name, profile = "USQUE", "сессия MASQUE"
	case "wireguard":
		name = "WireGuard"
	case "amneziawg":
		name = "AmneziaWG"
	}
	if !option.Installed {
		return name + ": исполняемый компонент недоступен."
	}
	if staged {
		return name + ": черновик сохранён, нужна проверка выбранного сервиса через этот кандидат."
	}
	if !option.Configured {
		return name + ": для выбранного пути отсутствует " + profile + "."
	}
	if !option.Running {
		return name + ": профиль найден, процесс или туннель сейчас не работает."
	}
	return name + ": готовность пути не подтверждена."
}
