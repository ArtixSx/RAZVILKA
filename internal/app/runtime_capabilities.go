package app

import (
	"github.com/ArtixSx/razvilka/internal/autonomy"
	"github.com/ArtixSx/razvilka/internal/config"
)

// Availability is advisory readback, never an admission token or live-health
// result. A nil Available explicitly leaves operation-specific checks pending.
type runtimeCapabilityAvailability struct {
	Available *bool  `json:"available"`
	State     string `json:"state"`
	Reason    string `json:"reason,omitempty"`
	Message   string `json:"message"`
}

// This is also the worker's early route gate. Passing it does not grant Apply:
// per-service scope, candidate evidence and transaction admission still follow.
func (a *App) autonomyRouteBlockReason(p autonomy.Policy, cfg config.Config) string {
	switch {
	case !p.SetupComplete:
		return "setup-incomplete"
	case !p.Enabled:
		return "policy-paused"
	case cfg.SafeMode:
		return "safe-mode"
	case cfg.ServiceControl.Stopped:
		return "stopped"
	case cfg.ServiceControl.EffectiveMode() == "manual":
		return "manual"
	case a.Dataplane == nil:
		return "dataplane-unavailable"
	default:
		return ""
	}
}
func (a *App) autonomyCapabilities(p autonomy.Policy, cfg config.Config, blocked bool, blockedCode string) map[string]any {
	implemented := map[string]bool{"automatic_initial_apply": true, "automatic_reserves": true, "automatic_install": true, "component_install": true}
	route := runtimeCapabilityAvailability{State: "requires-service-plan", Message: "Автопилот включён. Для каждого сервиса ещё нужны актуальные проверки узла, области и применения."}
	reason := a.autonomyRouteBlockReason(p, cfg)
	if blocked {
		reason = blockedCode
		if reason == "" {
			reason = "recovery-required"
		}
	}
	if reason != "" {
		available := false
		messages := map[string]string{"setup-incomplete": "Завершите настройку автопилота.", "policy-paused": "Автоматические изменения приостановлены политикой.", "safe-mode": "Безопасный режим блокирует автоматическое применение.", "stopped": "Собственные маршруты остановлены; автопилот не снимает Stop автоматически.", "manual": "Включён ручной режим управления.", "dataplane-unavailable": "Исполнитель маршрутов недоступен."}
		message := messages[reason]
		if message == "" {
			message = "Автопилот приостановлен: требуется проверка журнала и планировщика."
		}
		route = runtimeCapabilityAvailability{Available: &available, State: "blocked", Reason: reason, Message: message}
	}
	operation := runtimeCapabilityAvailability{State: "requires-operation-check", Message: "Доступность установки определяется её политикой, окном обслуживания, журналом и проверкой установщика."}
	return map[string]any{"schema": 1, "automatic_initial_apply": true, "automatic_reserves": true, "automatic_install": true, "component_install": true, "scenario": "web", "source_timers": "saved-router-subscriptions", "implemented": implemented, "availability": map[string]runtimeCapabilityAvailability{"automatic_initial_apply": route, "automatic_reserves": route, "automatic_install": operation, "component_install": operation}, "note": "Совместимые legacy-флаги и implemented описывают реализованные функции. availability — текущие ограничения; null требует проверки конкретной операции. Эти данные не подтверждают применённый маршрут, здоровье сервиса или аппаратную приёмку."}
}
