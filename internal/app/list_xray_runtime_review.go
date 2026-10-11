package app

import (
	"context"
	"errors"
	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/dataplane"
	"net/http"
	"reflect"
	"strings"
	"time"
)

func (e *managedXraySelectedTCPListExecution) applyReview(scope changeScope) applyReview {
	return applyReview{Revision: e.source.expected.Revision, Digest: applyReviewHash(struct {
		Kind, Config, Catalog, Compilation, Listener string
		Scope                                        changeScope
	}{"managed-xray-selected-tcp-443", applyReviewHash(e.source.expected), e.source.catalog, e.preparation.compilation.Digest(), e.listener.String(), scope})}
}

func (r *ManagedXraySelectedTCPListRuntime) review(ctx context.Context, serviceID string, scope changeScope) (plan dataplane.Plan, review applyReview, resultErr error) {
	if !r.original() {
		return plan, review, ErrXrayListSource
	}
	ctx, cancel := context.WithTimeout(ctx, 12*time.Second)
	defer cancel()
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.pending != nil || r.preparing != nil {
		return plan, review, ErrXrayListSource
	}
	if r.active != nil {
		return r.reviewActiveLocked(ctx, scope)
	}
	c, end, err := r.app.privateExclusiveOperation(ctx)
	if err != nil {
		return plan, review, err
	}
	defer end()
	if err := r.policy.control.Current(c); err != nil {
		return plan, review, err
	}
	if r.app.Store.Get().ServiceControl.Stopped {
		return plan, review, ErrXrayListSource
	}
	e := &managedXraySelectedTCPListExecution{runtime: r}
	e.self = e
	r.preparing = e
	defer func() { r.preparing = nil; resultErr = errors.Join(resultErr, e.close()) }()
	if _, err := e.prepare(c, serviceID); err != nil {
		return plan, review, err
	}
	if err := errors.Join(e.preparation.current(c), e.primary.Current(c)); err != nil {
		return plan, review, err
	}
	return defaultRouteClonePlan(e.plan), e.applyReview(scope), nil
}

func (r *ManagedXraySelectedTCPListRuntime) reviewActiveLocked(ctx context.Context, scope changeScope) (dataplane.Plan, applyReview, error) {
	if r.active == nil || r.active.preparation == nil {
		return dataplane.Plan{}, applyReview{}, ErrXrayListSource
	}
	if err := r.currentLocked(ctx); err != nil {
		return dataplane.Plan{}, applyReview{}, err
	}
	plan := defaultRouteClonePlan(r.active.plan)
	plan.State, plan.Noop = "committed", true
	return plan, r.active.applyReview(scope), nil
}

func (a *App) managedXrayApplyTarget(cfg config.Config, scope changeScope) (*ManagedXraySelectedTCPListRuntime, string, bool, error) {
	if cfg.NetworkPolicy == nil || scope != changeScopeAll && scope != changeScopeServices {
		return nil, "", false, nil
	}
	serviceID := ""
	for id, state := range cfg.Services {
		if !state.Enabled || !strings.HasPrefix(selectedRoute(state), "xray:node-") {
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
	a.managedXraySelectedTCPListMu.Lock()
	runtime := a.managedXraySelectedTCPList
	a.managedXraySelectedTCPListMu.Unlock()
	if runtime == nil {
		return nil, "", true, ErrXrayListSource
	}
	return runtime, serviceID, true, nil
}

func (a *App) managedXrayPlanHTTP(w http.ResponseWriter, r *http.Request, cfg config.Config, scope changeScope) bool {
	runtime, serviceID, handled, err := a.managedXrayApplyTarget(cfg, scope)
	if !handled {
		return false
	}
	if err != nil {
		writeManagedXrayRuntimeError(w, http.StatusConflict, "XRAY_SELECTED_TCP_REVIEW_REFUSED")
		return true
	}
	c, end := managedNFQRuntimeCallContext(r.Context(), "plan")
	defer end()
	plan, review, err := runtime.review(c, serviceID, scope)
	if err != nil {
		writeManagedXrayRuntimeError(w, http.StatusConflict, "XRAY_SELECTED_TCP_REVIEW_REFUSED")
		return true
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "scope": scope, "transaction": plan, "review": review, "service_health": "unverified", "traffic": "tcp/443", "change_summary": a.changeSummary(cfg, scope, plan)})
	return true
}

func (a *App) managedXrayApplyHTTP(w http.ResponseWriter, r *http.Request, cfg config.Config, scope changeScope, request applyReviewRequest) bool {
	runtime, serviceID, handled, err := a.managedXrayApplyTarget(cfg, scope)
	if !handled {
		return false
	}
	if err != nil || request.Revision == nil {
		writeManagedXrayRuntimeError(w, http.StatusConflict, "XRAY_SELECTED_TCP_REVIEW_REQUIRED")
		return true
	}
	c, end := managedNFQRuntimeCallContext(r.Context(), "apply")
	defer end()
	if err := managedNFQResponseDeadline(w, c); err != nil {
		writeManagedXrayRuntimeError(w, http.StatusServiceUnavailable, "XRAY_SELECTED_TCP_RESPONSE_UNAVAILABLE")
		return true
	}
	review := applyReview{Revision: *request.Revision, Digest: request.Digest}
	execution, err := runtime.startReviewed(c, serviceID, scope, &review)
	if err != nil {
		if errors.Is(err, dataplane.ErrReviewChanged) {
			writeManagedXrayRuntimeError(w, http.StatusConflict, "APPLY_REVIEW_CHANGED")
		} else {
			writeManagedXrayRuntimeError(w, http.StatusConflict, "XRAY_SELECTED_TCP_RUNTIME_REFUSED")
		}
		return true
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "scope": scope, "safe_mode": false, "live_applied": true, "execution": execution, "service_health": "unverified", "traffic": "tcp/443", "pending_changes": a.pendingChanges(), "scope_pending_changes": a.scopePendingChanges(scope, "")})
	return true
}

func writeManagedXrayRuntimeError(w http.ResponseWriter, status int, code string) {
	writeJSON(w, status, map[string]any{"ok": false, "code": code, "error": "Проверка исходного Xray TCP пути не завершена. Проверьте журнал и состояние маршрута.", "service_health": "unverified"})
}
