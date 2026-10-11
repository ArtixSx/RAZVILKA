package app

import (
	"errors"
	"net/http"
	"reflect"

	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/dataplane"
)

func (a *App) managedWGApplyTarget(cfg config.Config, scope changeScope) (*ManagedWGListRuntime, string, bool, error) {
	if cfg.NetworkPolicy == nil || scope != changeScopeAll && scope != changeScopeServices {
		return nil, "", false, nil
	}
	serviceID := ""
	for id, state := range cfg.Services {
		if !state.Enabled || !managedWGSelected(selectedRoute(state)) {
			continue
		}
		if serviceID != "" {
			return nil, "", true, ErrDefaultRouteCapability
		}
		serviceID = id
	}
	if serviceID == "" {
		return nil, "", false, nil
	}
	for id, state := range cfg.Services {
		if state.Enabled && id != serviceID && selectedRoute(state) != "direct" {
			return nil, "", true, ErrDefaultRouteCapability
		}
	}
	if scope == changeScopeServices && !reflect.DeepEqual(cfg.NetworkPolicy, cfg.AppliedNetworkPolicy) {
		return nil, "", true, ErrDefaultRouteCapability
	}
	a.managedWGListMu.Lock()
	runtime := a.managedWGList
	a.managedWGListMu.Unlock()
	if runtime == nil {
		return nil, "", true, dataplane.ErrWGOperationOwner
	}
	return runtime, serviceID, true, nil
}

func (a *App) managedWGPlanHTTP(w http.ResponseWriter, r *http.Request, cfg config.Config, scope changeScope) bool {
	runtime, serviceID, handled, err := a.managedWGApplyTarget(cfg, scope)
	if !handled {
		return false
	}
	if err != nil {
		writeManagedWGRuntimeError(w, http.StatusConflict, "WG_LIST_REVIEW_REFUSED")
		return true
	}
	c, end := managedNFQRuntimeCallContext(r.Context(), "plan")
	defer end()
	plan, review, err := runtime.review(c, serviceID, scope)
	if err != nil {
		writeManagedWGRuntimeError(w, http.StatusConflict, "WG_LIST_REVIEW_REFUSED")
		return true
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "scope": scope, "transaction": plan, "review": review, "service_health": "unverified", "change_summary": a.changeSummary(cfg, scope, plan)})
	return true
}

func (a *App) managedWGApplyHTTP(w http.ResponseWriter, r *http.Request, cfg config.Config, scope changeScope, request applyReviewRequest) bool {
	runtime, serviceID, handled, err := a.managedWGApplyTarget(cfg, scope)
	if !handled {
		return false
	}
	if err != nil || request.Revision == nil {
		writeManagedWGRuntimeError(w, http.StatusConflict, "WG_LIST_REVIEW_REQUIRED")
		return true
	}
	c, end := managedNFQRuntimeCallContext(r.Context(), "apply")
	defer end()
	if err := managedNFQResponseDeadline(w, c); err != nil {
		writeManagedWGRuntimeError(w, http.StatusServiceUnavailable, "WG_LIST_RESPONSE_UNAVAILABLE")
		return true
	}
	review := applyReview{Revision: *request.Revision, Digest: request.Digest}
	execution, err := runtime.startReviewed(c, serviceID, scope, &review)
	if err != nil {
		if errors.Is(err, dataplane.ErrReviewChanged) {
			writeManagedWGRuntimeError(w, http.StatusConflict, "APPLY_REVIEW_CHANGED")
		} else {
			writeManagedWGRuntimeError(w, http.StatusConflict, "WG_LIST_RUNTIME_REFUSED")
		}
		return true
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "scope": scope, "safe_mode": false, "live_applied": true, "execution": execution, "service_health": "unverified", "pending_changes": a.pendingChanges(), "scope_pending_changes": a.scopePendingChanges(scope, "")})
	return true
}

func writeManagedWGRuntimeError(w http.ResponseWriter, status int, code string) {
	writeJSON(w, status, map[string]any{"ok": false, "code": code, "error": "Проверка исходного WireGuard пути не завершена. Проверьте журнал и состояние маршрута.", "service_health": "unverified"})
}
