package app

import (
	"net/http"
	"slices"

	"github.com/ArtixSx/razvilka/internal/autonomy"
	"github.com/ArtixSx/razvilka/internal/config"
)

// The first wizard selects assignments. The existing network owner remains
// responsible for proving the allowed LAN and for enforcing its exclusions.
func initialAutonomyScope(cfg config.Config, before autonomy.Policy, saved bool) (allLAN bool, sources []string, managedLANOnly bool) {
	hasNetworkPolicy := cfg.NetworkPolicy != nil || cfg.AppliedNetworkPolicy != nil
	if saved {
		return before.AllLAN, slices.Clone(before.DefaultSources), before.AllLAN
	}
	if hasNetworkPolicy {
		return true, nil, true
	}
	// Old installations without an Auto journal can still have an explicit
	// per-service device limit. Keep those assignments exactly as saved and
	// grant no new default client scope from them.
	for _, services := range []map[string]config.ServiceState{cfg.Services, cfg.AppliedServices, cfg.ServiceControl.SuspendedServices} {
		for _, state := range services {
			if len(state.Sources) != 0 {
				return false, nil, false
			}
		}
	}
	for _, policy := range cfg.ServicePolicies {
		if len(policy.DeviceSources) != 0 {
			return false, nil, false
		}
	}
	return true, nil, true
}

func autonomyScopeRefusal(cfg config.Config, s autonomy.Service) string {
	if !s.AllLAN && len(s.Sources) == 0 {
		return "Сохранена пустая область устройств. Сервис ожидает выбора области."
	}
	if s.ManagedLANOnly && !config.CurrentDefaultRouteScopeConsent(cfg) {
		return "Область домашней сети ещё не подтверждена. Автопилот ждёт проверки её границ и исключений."
	}
	return ""
}

func initialScopeRevisionCurrent(cfg config.Config, p autonomy.Policy, revision uint64) bool {
	if cfg.NetworkPolicy == nil {
		// Only the explicitly limited legacy scope can be handed back without
		// a network policy. A missing policy must never manufacture Home consent.
		return revision == 0 && !p.AllLAN && !p.ManagedLANOnly
	}
	return revision != 0 && cfg.NetworkPolicy.Revision == revision && config.CurrentDefaultRouteScopeConsent(cfg)
}

func writeWizardScopeChanged(w http.ResponseWriter) {
	writeJSON(w, http.StatusConflict, map[string]any{"code": "NETWORK_POLICY_REVIEW_CHANGED", "error": "Область сети изменилась. Проверьте устройства и исключения перед сохранением мастера."})
}
