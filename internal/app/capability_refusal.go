package app

import (
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/ArtixSx/razvilka/internal/config"
)

// Stable codes of known product limits. A capability refusal is not a failed
// or unfinished check: the saved choice can never be applied as it is, so a
// repeated Apply or autopilot attempt cannot help until the owner changes it.
const (
	capabilityExecutorRequired = "NETWORK_POLICY_EXECUTOR_REQUIRED"
	capabilityServiceDomains   = "SERVICE_HAS_DOMAINS"
	capabilitySingleService    = "LIST_MODE_SINGLE_SERVICE"
	capabilityPlatformProfile  = "PLATFORM_PROFILE_UNSUPPORTED"
)

// capabilityRefusal is decided from the saved configuration, the catalog and
// the list startup owner's fixed failure stage, before any plan admission,
// Stage or effect. It grants nothing: a choice it lets through still meets
// every check of the original owners, which keep their own refusals.
type capabilityRefusal struct {
	Code, Title, Message, Resolution string
	ServiceID                        string
}

func (e *capabilityRefusal) Error() string { return e.Code + ": " + e.Message }

// Nothing was attempted, so the response may say that working routes did not
// change. The draft stays as saved; repeating the same request cannot pass.
func writeCapabilityRefusal(w http.ResponseWriter, refusal *capabilityRefusal) {
	message := refusal.Message + " Рабочие маршруты не менялись."
	writeJSON(w, http.StatusConflict, map[string]any{
		"ok": false, "code": refusal.Code, "capability_refusal": true,
		"error": message, "resolution": refusal.Resolution, "service_id": refusal.ServiceID,
		"failure":      applyFailureAdvice{Code: refusal.Code, Title: refusal.Title, Message: message, Resolution: refusal.Resolution, DraftPreserved: true},
		"live_applied": false, "working_routes_changed": false, "review_required": false,
	})
}

// The legacy builder stays closed while a list policy or a stored negative
// exists. Only the saved configuration is read, so this refusal still
// precedes every catalog, detector and journal read of the builder.
func legacyExecutorRefusal(cfg config.Config) *capabilityRefusal {
	if cfg.NetworkPolicy == nil && cfg.AppliedNetworkPolicy == nil {
		return &capabilityRefusal{Code: capabilityExecutorRequired, Title: "Мешает список «Сайты без обхода»",
			Message:    "Сохранён список «Сайты без обхода», а исключения сайтов работают только в режиме «Домашняя сеть». Обычное применение остановлено, чтобы они не были молча проигнорированы.",
			Resolution: "Очистите список «Сайты без обхода» — тогда обычное применение снова доступно."}
	}
	return &capabilityRefusal{Code: capabilityExecutorRequired, Title: "Недоступно в режиме «Домашняя сеть»",
		Message:    "В режиме «Домашняя сеть» применяется только один сервис с IP-диапазонами (CIDR) через NFQWS2, узел Xray или WireGuard/AmneziaWG; этот выбор так не применяется.",
		Resolution: "Оставьте один такой сервис и выберите для него NFQWS2, узел Xray или WireGuard. Чтобы выключить обход, используйте общий переключатель проекта."}
}

func platformProfileRefusal() *capabilityRefusal {
	return &capabilityRefusal{Code: capabilityPlatformProfile, Title: "Режим «Домашняя сеть» недоступен на этом роутере",
		Message:    "Режим «Домашняя сеть» не запущен: при старте роутер не подтвердился как Netcraze Ultra (NC-1812) с прошивкой 5.01.C.6.0-1, а другие пока не поддерживаются.",
		Resolution: "Если это NC-1812 с этой прошивкой, перезапустите RAZVILKA: профиль проверится заново."}
}

// The list policy owner pins one reviewed router profile at startup. A failed
// network-identity stage means this router was not confirmed as that profile,
// so no list lane exists until RAZVILKA starts again.
func (a *App) listPolicyPlatformUnconfirmed() bool {
	a.managedListPolicyMu.Lock()
	defer a.managedListPolicyMu.Unlock()
	p := a.managedListPolicy
	return p != nil && p.startupFailure != nil && ManagedListStartupFailureStage(p.startupFailure) == "network-identity"
}

// listModeCapabilityRefusal names a list-mode limit that every managed lane
// would refuse anyway, before any of them reads or admits anything. It is
// narrower than their checks; the lanes still refuse what it lets through.
func (a *App) listModeCapabilityRefusal(cfg config.Config, scope changeScope) *capabilityRefusal {
	if cfg.NetworkPolicy == nil || scope != changeScopeAll && scope != changeScopeServices {
		return nil
	}
	if a.listPolicyPlatformUnconfirmed() {
		return platformProfileRefusal()
	}
	return a.listModeServiceRefusal(cfg)
}

// Bypassed means enabled and not "direct", as the WireGuard and Xray lanes
// count other services. Every lane carries exactly one such service, and only
// one without catalog domains.
func (a *App) listModeServiceRefusal(cfg config.Config) *capabilityRefusal {
	ids := make([]string, 0, len(cfg.Services))
	for id, state := range cfg.Services {
		if state.Enabled && selectedRoute(state) != "direct" {
			ids = append(ids, id)
		}
	}
	if len(ids) == 0 {
		return nil
	}
	sort.Strings(ids)
	names, domains := map[string]string{}, map[string]bool{}
	for _, service := range a.catalogSnapshot().Services {
		names[service.ID], domains[service.ID] = service.Name, len(service.Domains) != 0
	}
	name := func(id string) string {
		if names[id] != "" {
			return names[id]
		}
		return id
	}
	if len(ids) > 1 {
		shown := make([]string, 0, 3)
		for _, id := range ids[:min(3, len(ids))] {
			shown = append(shown, "«"+name(id)+"»")
		}
		list := strings.Join(shown, ", ")
		if len(ids) > len(shown) {
			list += fmt.Sprintf(" и ещё %d", len(ids)-len(shown))
		}
		return &capabilityRefusal{Code: capabilitySingleService, Title: "В режиме «Домашняя сеть» — один сервис",
			Message:    fmt.Sprintf("Режим «Домашняя сеть» пока обходит только один сервис, а включено %d: %s.", len(ids), list),
			Resolution: "Оставьте с обходом один сервис, остальные выключите или переведите на «Напрямую»."}
	}
	if domains[ids[0]] {
		return &capabilityRefusal{Code: capabilityServiceDomains, Title: "Сервис задан доменами", ServiceID: ids[0],
			Message:    "Сервис «" + name(ids[0]) + "» задан доменами, а режим «Домашняя сеть» пока применяет только сервисы с IP-диапазонами (CIDR).",
			Resolution: "Выключите его или используйте сервис с IP-диапазонами без доменов."}
	}
	return nil
}
