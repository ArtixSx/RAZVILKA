package app

import (
	"context"
	"errors"
	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/dataplane"
	"log"
	"net/http"
	"reflect"
	"strings"
	"time"
)

// Native stock observation cost requires a whole-review budget longer than
// one physical read. Earlier caller deadlines and all leaf budgets still win.
const managedXrayPlanReviewTimeout = 60 * time.Second

func managedXrayReviewContext(parent context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(parent, managedXrayPlanReviewTimeout)
}

func managedXrayCompleteReview(ctx context.Context, stage string, plan dataplane.Plan, review applyReview, err error) (dataplane.Plan, applyReview, error) {
	// Cleanup must join even after cancellation. Its completion cannot turn a
	// now-expired forward review into a successful response.
	if err == nil && ctx.Err() != nil {
		plan, review, err = dataplane.Plan{}, applyReview{}, ctx.Err()
	}
	return plan, review, managedXrayReviewAt(stage, ctx, err)
}

func (e *managedXraySelectedTCPListExecution) applyReview(scope changeScope) applyReview {
	return applyReview{Revision: e.source.expected.Revision, Digest: applyReviewHash(struct {
		Kind, Config, Catalog, Compilation, Listener string
		Scope                                        changeScope
	}{"managed-xray-selected-tcp-443", applyReviewHash(e.source.expected), e.source.catalog, e.preparation.compilation.Digest(), e.listener.String(), scope})}
}

func (r *ManagedXraySelectedTCPListRuntime) review(ctx context.Context, serviceID string, scope changeScope) (plan dataplane.Plan, review applyReview, resultErr error) {
	if !r.original() {
		return plan, review, managedXrayReviewAt("admission", ctx, ErrXrayListSource)
	}
	ctx, cancel := managedXrayReviewContext(ctx)
	defer cancel()
	ctx, finishTimings := beginManagedNFQTimings(ctx)
	defer func() { finishTimings("xray-review", resultErr) }()
	stage := "admission"
	// Runs after the original cleanup/unlock, but before this review's cancel.
	// Only a real failed boundary may retain the actual caller/deadline cause.
	defer func() { plan, review, resultErr = managedXrayCompleteReview(ctx, stage, plan, review, resultErr) }()
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.pending != nil || r.preparing != nil {
		return plan, review, ErrXrayListSource
	}
	if r.active != nil {
		stage = "final-check"
		return r.reviewActiveLocked(ctx, scope)
	}
	c, end, err := r.app.privateExclusiveOperation(ctx)
	if err != nil {
		return plan, review, err
	}
	defer end()
	stage = "control"
	if err := r.policy.control.Current(c); err != nil {
		return plan, review, err
	}
	if r.app.Store.Get().ServiceControl.Stopped {
		return plan, review, ErrXrayListSource
	}
	e := &managedXraySelectedTCPListExecution{runtime: r}
	e.self = e
	r.preparing = e
	defer func() {
		r.preparing = nil
		cleanupErr := e.close()
		resultErr = errors.Join(resultErr, cleanupErr)
		if cleanupErr != nil {
			stage = "cleanup"
		}
	}()
	stage = "prepare"
	if _, err := e.prepare(c, serviceID); err != nil {
		return plan, review, err
	}
	stage = "final-check"
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
	started := time.Now()
	runtime, serviceID, handled, err := a.managedXrayApplyTarget(cfg, scope)
	if !handled {
		return false
	}
	if err != nil {
		writeManagedXrayReviewError(w, managedXrayReviewAt("target", r.Context(), err), started)
		return true
	}
	c, end := managedNFQRuntimeCallContext(r.Context(), "plan")
	defer end()
	plan, review, err := runtime.review(c, serviceID, scope)
	if err != nil {
		writeManagedXrayReviewError(w, err, started)
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

// The phase is an internal boundary label, never an error message or source
// identity. This observation adds no timer, admission or runtime permission.
func logManagedXrayPrepareFailure(phase string, elapsed time.Duration, err error) {
	if err == nil {
		return
	}
	switch phase {
	case "input", "scope-acquire", "source-review", "source-prepare", "shape", "primary-review", "material-review", "plan-build", "closing-current":
	default:
		phase = "unclassified"
	}
	log.Printf("Managed Xray prepare refused substage=%s elapsed_ms=%d", phase, max(int64(0), min(elapsed.Milliseconds(), int64(120000))))
}

func logManagedXrayReviewClose(phase string, elapsed time.Duration, err error) {
	if phase != "source-close" && phase != "scope-close" {
		phase = "unclassified"
	}
	cause := "none"
	if err != nil {
		cause = "refused"
	}
	log.Printf("Managed Xray review close stage=%s cause=%s elapsed_ms=%d", phase, cause, max(int64(0), min(elapsed.Milliseconds(), int64(120000))))
}
