package app

import (
	"errors"
	"strings"

	"github.com/ArtixSx/razvilka/internal/autonomy"
	"github.com/ArtixSx/razvilka/internal/config"
)

// errAutonomyPlanNotReady marks an autopilot Apply refused while its plan was
// built: no Stage started, so there is nothing to roll back.
var errAutonomyPlanNotReady = errors.New("autonomous plan not ready")

// autonomyCapabilityRefusal names a limit of the saved mode that makes the
// autopilot's Apply of route for serviceID impossible. It is pure: no probe,
// node check, plan or budget is used. A node route may be given by its
// engine prefix ("xray:node-"). The legacy path is closed exactly as the
// builder closes it; in list mode only the managed Xray lane is wired to the
// autopilot, for selected devices and one bypassed CIDR-only service.
func (a *App) autonomyCapabilityRefusal(cfg config.Config, serviceID, route string) *capabilityRefusal {
	if cfg.NetworkPolicy == nil {
		if cfg.AppliedNetworkPolicy == nil {
			return nil
		}
		return legacyExecutorRefusal(cfg)
	}
	if a.listPolicyPlatformUnconfirmed() {
		return platformProfileRefusal()
	}
	// The service's own domains block it even when it is the only one, so
	// they are named before the count of other bypassed services.
	planned := config.Config{Services: map[string]config.ServiceState{serviceID: {Enabled: true, Route: route}}}
	if refusal := a.listModeServiceRefusal(planned); refusal != nil {
		return refusal
	}
	for id, state := range cfg.Services {
		if id != serviceID {
			planned.Services[id] = state
		}
	}
	if refusal := a.listModeServiceRefusal(planned); refusal != nil {
		return refusal
	}
	if strings.HasPrefix(route, "xray:node-") && cfg.NetworkPolicy.Clients.Mode == "selected_devices" {
		return nil
	}
	return &capabilityRefusal{Code: capabilityExecutorRequired, Title: "Автопилот не включает этот путь", ServiceID: serviceID,
		Message:    "В режиме «Домашняя сеть» автопилот пока включает сервис с IP-диапазонами только через узел Xray и только для выбранных устройств.",
		Resolution: "Выберите для сервиса узел Xray или примените его вручную через NFQWS2 или WireGuard."}
}

// Before any probe of an unapplied service, refuse only when every route the
// round could apply (each preferred route and the node route of its engine)
// is closed by the saved mode. The node route's refusal is reported.
func (a *App) autonomyUnappliedRefusal(cfg config.Config, p autonomy.Policy, s autonomy.Service, engine string) *capabilityRefusal {
	refusal := a.autonomyCapabilityRefusal(cfg, s.ID, engine+":node-")
	if refusal == nil {
		return nil
	}
	for _, route := range p.PreferredRoutes {
		if a.autonomyCapabilityRefusal(cfg, s.ID, route) == nil {
			return nil
		}
	}
	return refusal
}

// A capability refusal is terminal for the current settings: the round says
// what to change and does not promise a retry. Nothing was attempted, so a
// switch reserved for it is returned. Later rounds repeat only this pure
// check until the owner changes the mode, the list or the service.
func autonomyCapabilityRefused(refusal *capabilityRefusal, r *autonomy.Runtime) autonomy.Runtime {
	r.State = "capability-refused"
	// Title and action only: the full explanation is in the Apply refusal.
	r.Message = refusal.Title + ". " + refusal.Resolution + " Автопилот ждёт изменения настроек."
	return *r
}

// Outcomes of a refused autopilot Apply that started nothing: the switch
// reservation is returned and no rollback is claimed.
func autonomyNotStarted(err error, r *autonomy.Runtime) (string, string, bool) {
	var refusal *capabilityRefusal
	if errors.As(err, &refusal) {
		r.RefundSwitch()
		next := autonomyCapabilityRefused(refusal, r)
		return next.State, next.Message, true
	}
	if errors.Is(err, errAutonomyPlanNotReady) {
		r.RefundSwitch()
		return "apply-refused", "План применения не готов, поэтому применение не начиналось. Рабочие маршруты не менялись; автопилот повторит попытку позже.", true
	}
	return "", "", false
}

// A non-node route is carried only by the legacy transaction, whose attempted
// failures are typed. Rollback wording is kept for an attempted transaction;
// a refusal before Stage returns the switch reservation instead.
func autonomyLegacyApplyRefused(err error, r *autonomy.Runtime, attempted string) (string, string) {
	if state, message, blocked := autonomyRouteDependency(err, r); blocked {
		return state, message
	}
	var failed *autonomyApplyFailure
	if errors.As(err, &failed) {
		return "apply-refused", attempted
	}
	r.RefundSwitch()
	return "apply-refused", "Применение не начиналось: условия проверки изменились или не подтверждены. Рабочие маршруты не менялись; автопилот повторит попытку."
}
