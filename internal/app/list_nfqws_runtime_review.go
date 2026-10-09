package app

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net/http"
	"reflect"
	"time"

	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/strategylab"
)

// prepare uses original source, component and physical readers. Its plan is
// comparison data; only the same retained owners may perform actual effects.
func (e *managedNFQWSListExecution) prepare(c context.Context, serviceID, protocol, family string) (compilation *DefaultRouteCompilation, err error) {
	phase := "physical-scope"
	defer func() { err = managedNFQFailureAt(phase, err) }()
	r, cfg := e.runtime, e.expected
	phase = "physical-scope"
	e.scope, err = NewReviewedStockNC1812ListScopeBinding(c, r.app, r.provider)
	if err != nil {
		return nil, err
	}
	phase = "component"
	e.component, err = r.app.Components.AcquireCurrentManagedNFQWSRuntime(c)
	if err != nil {
		return nil, err
	}
	phase = "selected-source"
	e.source, err = r.app.StrategyLab.RetainSelectedCandidateReview(c, serviceID, protocol, family, e.component)
	if err != nil {
		return nil, err
	}
	phase = "source-compare"
	reference, err := defaultRouteNFQWSReference(c, e.source)
	if err != nil {
		return nil, err
	}
	phase = "physical-observe"
	snapshot, err := e.scope.Observe(c)
	if err != nil {
		return nil, err
	}
	phase = "catalog-services"
	var services []dataplane.Route
	for _, service := range r.app.catalogSnapshot().Services {
		state := cfg.Services[service.ID]
		if !state.Enabled {
			continue
		}
		if service.ID != serviceID || state.Route != "nfqws2" || len(service.Domains) != 0 || len(service.SourceRefs) != 0 || len(service.CIDRs) == 0 || service.ProbeURL == "" {
			return nil, ErrDefaultRouteCapability
		}
		services = append(services, dataplane.Route{ServiceID: service.ID, ServiceName: service.Name, Selected: "nfqws2", Resolved: "nfqws2", CIDRs: append([]string(nil), service.CIDRs...), Sources: append([]string(nil), state.Sources...), ProbeURL: service.ProbeURL})
		snapshot.Paths = map[string]DefaultRoutePath{service.ID: {Selected: "nfqws2", Resolved: "nfqws2", ProbeURL: service.ProbeURL, NFQWS: &reference}}
	}
	if len(services) != 1 {
		return nil, ErrDefaultRouteCapability
	}
	phase = "compile"
	compilation, err = CompileDefaultRoutePolicy(cfg, snapshot, services, time.Now())
	if err != nil {
		return nil, err
	}
	phase = "bind-compilation"
	if err := e.scope.BindCompilation(c, compilation); err != nil {
		return nil, err
	}
	adapter, ok := r.manager.Adapters["nfqws2"].(*dataplane.NFQWS2Adapter)
	if !ok {
		return nil, dataplane.ErrNFQWSScopedOwner
	}
	// Mint the bounded native material after the slow original physical review.
	phase = "active-material"
	e.material, err = dataplane.ReviewManagedNFQWSActiveMaterial(c, r.manager, adapter, e.source, e.component, r.control, r.app.SelfUpdateFiles.ControlRoot, r.provider, managedNFQWSListQueue)
	if err != nil {
		return nil, err
	}
	input := (&DefaultRouteExecutor{app: r.app}).input(compilation, cfg)
	phase = "native-plan"
	plan, err := dataplane.BuildManagedNFQWSList(c, input, e.material, time.Now())
	if err != nil || !plan.Ready {
		return nil, errors.Join(ErrDefaultRouteCapability, err)
	}
	plan.Digest = defaultRouteDigest(struct{ Plan, Policy string }{plan.Digest, compilation.Digest()})
	var nonce [8]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, err
	}
	plan.PlanID = "dp-" + plan.Digest[:16] + "-" + hex.EncodeToString(nonce[:])
	e.plan = defaultRouteClonePlan(plan)
	var matches []dataplane.NFQWSScopedMatch
	for _, rule := range compilation.Rules() {
		if rule.ServiceID != serviceID || rule.Route != "nfqws2" {
			return nil, ErrDefaultRouteCapability
		}
		matches = append(matches, dataplane.NFQWSScopedMatch{ServiceID: rule.ServiceID, Origin: rule.Origin, Route: rule.Route, Ingress: rule.Ingress, Source: rule.Source, Destination: rule.Destination, Protocol: rule.Protocol, FirstPort: rule.FirstPort, LastPort: rule.LastPort})
	}
	phase = "selection-scope"
	e.selection, err = e.material.ReviewScope(c, reference, e.plan, matches)
	if err != nil {
		return nil, err
	}
	e.compilation = compilation
	return compilation, nil
}

// The native session/command nonce is minted afresh by prepare. Intent binds
// the stable complete compilation (including original source/control/physical
// comparisons), full Store and catalog instead of reusing an old native nonce.
// This digest is presentation/confirmation only, never an effect capability.
func (e *managedNFQWSListExecution) applyReview(compilation *DefaultRouteCompilation, scope changeScope) applyReview {
	return applyReview{Revision: e.expected.Revision, Digest: applyReviewHash(struct {
		Kind, Config, Catalog, Compilation string
		Scope                              changeScope
	}{"managed-nfqws-list", applyReviewHash(e.expected), e.catalog, compilation.Digest(), scope})}
}

func (r *ManagedNFQWSListRuntime) review(ctx context.Context, serviceID, protocol, family string, scope changeScope) (plan dataplane.Plan, review applyReview, resultErr error) {
	if !r.original() {
		return plan, review, dataplane.ErrNFQWSScopedOwner
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || r.pending != nil || r.active != nil || r.panel.Err() != nil {
		if r.active != nil && !r.closed && r.pending == nil && r.panel.Err() == nil {
			return r.reviewActiveLocked(ctx, scope)
		}
		return plan, review, dataplane.ErrNFQWSScopedOwner
	}
	c, release, err := r.app.privateExclusiveOperation(ctx)
	if err != nil {
		return plan, review, err
	}
	defer release()
	if err := r.control.Current(c); err != nil {
		return plan, review, err
	}
	e := &managedNFQWSListExecution{runtime: r, expected: r.app.Store.Get(), catalog: applyReviewHash(r.app.catalogSnapshot())}
	e.self = e
	defer func() { resultErr = errors.Join(resultErr, e.close()) }()
	compilation, err := e.prepare(c, serviceID, protocol, family)
	if err != nil {
		return plan, review, err
	}
	// No command admission is issued and no execution/Store publication occurs.
	if err := errors.Join(r.control.Current(c), e.source.Current(c), e.component.Check(c), e.scope.ScopeCheck(c, e.plan.LAN), e.material.Current(c)); err != nil {
		return plan, review, err
	}
	if !reflect.DeepEqual(r.app.Store.Get(), e.expected) || applyReviewHash(r.app.catalogSnapshot()) != e.catalog {
		return plan, review, dataplane.ErrReviewChanged
	}
	return defaultRouteClonePlan(e.plan), e.applyReview(compilation, scope), nil
}

// Inspection of the original active execution borrows the same fresh finite
// observer as Current. Serialized committed intent alone cannot yield a no-op
// or authorize a new Apply. A changed draft still fails its original guards.
func (r *ManagedNFQWSListRuntime) reviewActiveLocked(ctx context.Context, scope changeScope) (dataplane.Plan, applyReview, error) {
	if r.active == nil || r.active.compilation == nil {
		return dataplane.Plan{}, applyReview{}, dataplane.ErrNFQWSScopedOwner
	}
	if err := r.currentLocked(ctx); err != nil {
		return dataplane.Plan{}, applyReview{}, err
	}
	plan := defaultRouteClonePlan(r.active.plan)
	plan.State, plan.Noop = "committed", true
	return plan, r.active.applyReview(r.active.compilation, scope), nil
}

// Only the concrete selected-services NFQ list is handled here. The target is
// derived from actual saved metadata; RetainSelectedCandidateReview in prepare
// separately proves its original native compatibility and runtime ownership.
func (a *App) managedNFQApplyTarget(cfg config.Config, scope changeScope) (runtime *ManagedNFQWSListRuntime, serviceID, protocol, family string, handles bool, err error) {
	if cfg.NetworkPolicy == nil || scope != changeScopeAll && scope != changeScopeServices {
		return
	}
	for id, state := range cfg.Services {
		if state.Enabled && selectedRoute(state) == "nfqws2" {
			handles = true
			if serviceID != "" {
				return nil, "", "", "", true, ErrDefaultRouteCapability
			}
			serviceID = id
		}
	}
	if !handles {
		return
	}
	if scope == changeScopeServices && !reflect.DeepEqual(cfg.NetworkPolicy, cfg.AppliedNetworkPolicy) {
		return nil, "", "", "", true, ErrDefaultRouteCapability
	}
	if a.StrategyLab == nil {
		return nil, "", "", "", true, ErrDefaultRouteCapability
	}
	for _, selection := range a.StrategyLab.Snapshot().Selections {
		if selection.ServiceID != serviceID || selection.Mode != strategylab.ModeManual || !selection.Frozen {
			continue
		}
		if protocol != "" {
			return nil, "", "", "", true, ErrDefaultRouteCapability
		}
		protocol, family = selection.Protocol, selection.IPFamily
	}
	a.managedNFQListMu.Lock()
	runtime = a.managedNFQList
	a.managedNFQListMu.Unlock()
	if runtime == nil || protocol == "" {
		err = ErrDefaultRouteCapability
	}
	return
}

func (a *App) managedNFQPlanHTTP(w http.ResponseWriter, r *http.Request, cfg config.Config, scope changeScope) bool {
	runtime, serviceID, protocol, family, handles, err := a.managedNFQApplyTarget(cfg, scope)
	if !handles {
		return false
	}
	if err != nil {
		writeManagedNFQRuntimeError(w, http.StatusConflict, "NETWORK_POLICY_EXECUTOR_REQUIRED")
		return true
	}
	ctx, cancel := managedNFQRuntimeCallContext(r.Context(), "plan")
	defer cancel()
	plan, review, err := runtime.review(ctx, serviceID, protocol, family, scope)
	if err != nil {
		logManagedNFQRuntimeFailure("plan", err)
		writeManagedNFQRuntimeError(w, http.StatusConflict, "MANAGED_NFQWS_REVIEW_REFUSED")
		return true
	}
	var rows []map[string]any
	for _, route := range plan.Routes {
		rows = append(rows, map[string]any{"service": route.ServiceName, "id": route.ServiceID, "service_id": route.ServiceID, "selected_route": route.Selected, "engine": route.Resolved, "domains": len(route.Domains), "cidrs": len(route.CIDRs), "source_refs": route.SourceRefs})
	}
	writeJSON(w, http.StatusOK, map[string]any{"safe_mode": cfg.SafeMode, "scope": scope, "routes": rows, "transaction": plan, "review": review, "service_health": "unverified", "change_summary": a.changeSummary(cfg, scope, plan)})
	return true
}

func (a *App) managedNFQApplyHTTP(w http.ResponseWriter, r *http.Request, cfg config.Config, scope changeScope, request applyReviewRequest) bool {
	runtime, serviceID, protocol, family, handles, err := a.managedNFQApplyTarget(cfg, scope)
	if !handles {
		return false
	}
	if err != nil || request.Revision == nil {
		writeManagedNFQRuntimeError(w, http.StatusConflict, "MANAGED_NFQWS_REVIEW_REQUIRED")
		return true
	}
	ctx, cancel := managedNFQRuntimeCallContext(r.Context(), "apply")
	defer cancel()
	review := applyReview{Revision: *request.Revision, Digest: request.Digest}
	execution, err := runtime.startReviewed(ctx, serviceID, protocol, family, scope, &review)
	if err != nil {
		logManagedNFQRuntimeFailure("apply", err)
		if errors.Is(err, dataplane.ErrReviewChanged) {
			// The same sentinel can surface after actual effects. Keep the
			// normal review code without claiming unchanged working routes.
			writeJSON(w, http.StatusConflict, map[string]any{"ok": false, "code": "APPLY_REVIEW_CHANGED", "error": "Исходная область или подтверждённый план изменились. Проверьте журнал и откройте новый план.", "review_required": true, "service_health": "unverified"})
		} else {
			// Never describe a potentially changed/unknown execution as no-op.
			writeManagedNFQRuntimeError(w, http.StatusConflict, "MANAGED_NFQWS_RUNTIME_REFUSED")
		}
		return true
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "scope": scope, "safe_mode": false, "live_applied": true, "execution": execution, "service_health": "unverified", "pending_changes": a.pendingChanges(), "scope_pending_changes": a.scopePendingChanges(scope, "")})
	return true
}
