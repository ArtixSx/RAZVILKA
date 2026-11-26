package app

import (
	"context"
	"errors"
	"net/http"
	"reflect"
	"strings"
	"time"

	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/operationgate"
)

var errDataplaneBootRecovery = errors.Join(operationgate.ErrJournalRecovery, errors.New("dataplane boot recovery requires review"))

// A legacy flag may be retired, but the same hidden gate still protects an
// unresolved boot recovery. All public paths that clear it share this check.
func (a *App) clearRetiredSafeMode() error {
	if a.PendingSelfUpdateRecovery() {
		return errSelfUpdateRecovery
	}
	if a.PendingComponentRecovery() {
		return errComponentRecovery
	}
	if err := a.bootRecoveryPending(); err != nil {
		return err
	}
	return a.Store.SetSafeMode(false)
}

func (a *App) bootRecoveryPending() error {
	if a.Dataplane == nil {
		return nil
	}
	status, err := a.Dataplane.Status()
	if err != nil {
		return errDataplaneBootRecovery
	}
	recovery := status.Recovery
	if recovery == nil || !recovery.Guarded && recovery.State != "degraded" && recovery.State != "safe-mode" {
		return nil
	}
	// A completed explicit recovery/Stop may publish a new committed plan.
	// An old recovery record must not turn into a permanent legacy flag.
	if recovery.PlanID != "" && status.CommittedPlan != nil && status.CommittedPlan.PlanID != recovery.PlanID {
		return nil
	}
	return errDataplaneBootRecovery
}

// Runtime control uses the existing transaction manager and adapter ownership
// checks. It never calls system service stop/restart commands.
func (a *App) serviceControlRuntime(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	var request struct {
		ExpectedRevision *uint64 `json:"expected_revision"`
		Action           string  `json:"action"`
		Confirm          string  `json:"confirm"`
		IdempotencyKey   string  `json:"idempotency_key,omitempty"`
	}
	if !decodeServiceControl(w, r, &request) {
		return
	}
	if request.ExpectedRevision == nil || request.Action != "stop" && request.Action != "resume" || request.Action == "stop" && request.Confirm != "STOP_OWNED_ROUTES" || request.Action == "resume" && request.Confirm != "RESUME_OWNED_ROUTES" {
		http.Error(w, "Подтвердите включение или остановку маршрутов проекта.", http.StatusBadRequest)
		return
	}
	if a.PendingSelfUpdateRecovery() {
		if request.Action == "stop" {
			a.requestSelfUpdateRuntimeStop(w, r, *request.ExpectedRevision)
		} else {
			a.writeOperationFailure(w, errSelfUpdateRecovery)
		}
		return
	}
	if request.IdempotencyKey != "" {
		job, err := a.enqueueDurableServiceJob(r.Context(), serviceControlJobRequest{Kind: request.Action, ExpectedRevision: request.ExpectedRevision, IdempotencyKey: request.IdempotencyKey})
		if err != nil {
			a.writeDurableJobFailure(w, err)
			return
		}
		writeJSON(w, http.StatusAccepted, map[string]any{"job": job.presentation(), "persistent": true})
		return
	}
	// Older clients keep the synchronous contract; production UI sends a key.
	if handled, outcome := a.executeManagedServiceRuntime(r.Context(), request.Action, *request.ExpectedRevision); handled {
		status := http.StatusOK
		response := map[string]any{"ok": outcome.Code == "", "live_applied": outcome.LiveApplied}
		if outcome.Code != "" {
			status = http.StatusConflict
			response["code"], response["error"] = outcome.Code, outcome.Message
		} else {
			response["control"] = a.serviceControlView(r.Context())
		}
		writeJSON(w, status, response)
		return
	}
	ctx, release, err := a.scopedRuntimeOperation(componentStopContext(r.Context(), request.Action))
	if err != nil {
		a.writeOperationFailure(w, err)
		return
	}
	defer release()
	outcome := a.executeServiceRuntime(ctx, request.Action, *request.ExpectedRevision)
	status := http.StatusOK
	response := map[string]any{"ok": outcome.Code == "", "live_applied": outcome.LiveApplied}
	if outcome.Code != "" {
		status = http.StatusConflict
		response["code"], response["error"] = outcome.Code, outcome.Message
	} else {
		response["control"] = a.serviceControlView(r.Context())
	}
	if outcome.Execution != nil {
		response["execution"] = outcome.Execution
	}
	if outcome.Failure != nil {
		response["failure"] = outcome.Failure
	}
	writeJSON(w, status, response)
}

type serviceRuntimeOutcome struct {
	Code        string
	Message     string
	LiveApplied bool
	Execution   *dataplane.Execution
	Failure     *applyFailureAdvice
	// Memory-only receipt of the actual original managed Xray terminal Stop.
	// Durable requests and responses never carry cleanup authority or this proof.
	originalManagedXrayStop *managedXrayStopCompletion
}

func (a *App) observeCommittedRuntime(ctx context.Context, plan dataplane.Plan) error {
	if handled, err := a.observeCommittedMihomo(ctx, plan); handled {
		return err
	}
	if handled, err := a.observeCommittedManagedWG(ctx, plan); handled {
		return err
	}
	if handled, err := a.observeCommittedManagedXray(ctx, plan); handled {
		return err
	}
	if handled, err := a.observeCommittedManagedNFQ(ctx, plan); handled {
		return err
	}
	return a.Dataplane.ObserveCommittedRuntime(ctx, plan)
}

// Caller owns exclusive admission through transaction cleanup. This core has
// no HTTP lifetime: the reconciler can finish an accepted intent after logout.
func (a *App) executeServiceRuntime(parent context.Context, action string, expectedRevision uint64) serviceRuntimeOutcome {
	fail := func(code, message string) serviceRuntimeOutcome {
		return serviceRuntimeOutcome{Code: code, Message: message}
	}
	if a.Store == nil || a.Dataplane == nil {
		return fail("SERVICE_RUNTIME_UNAVAILABLE", "Управление маршрутами недоступно.")
	}
	cfg := a.Store.Get()
	if cfg.Revision != expectedRevision {
		return fail("SERVICE_CONTROL_CHANGED", "Настройки изменились. Обновите состояние и повторите действие.")
	}
	stop := action == "stop"
	// The original Xray owner may have changed between dispatch and exclusive admission.
	if stop && a.Dataplane.HasPendingManagedXraySelectedTCP() {
		return fail("SERVICE_RUNTIME_CHANGED", "Исходная транзакция Xray ещё не завершена. Откройте журнал перед остановкой.")
	}
	var recoveryStop *nfqRecoveryStopReview
	if cfg.SafeMode && action == "stop" && a.recoveryStopReviewRequired(parent, cfg) {
		var reviewErr error
		recoveryStop, reviewErr = a.reviewNFQRecoveryStop(parent, cfg)
		if reviewErr != nil {
			return fail("DATAPLANE_RECOVERY_REQUIRED", "Остановка требует подтверждения, что процессы и правила проекта уже отсутствуют.")
		}
	}
	if cfg.SafeMode && recoveryStop == nil {
		// Safe Mode was removed. The operator's own Start/Stop clears a flag an
		// older build or an offline restore left, unless an update still owns it.
		if err := a.clearRetiredSafeMode(); err != nil {
			return fail("DATAPLANE_RECOVERY_REQUIRED", "Восстановление маршрутов не подтверждено. Сначала завершите проверку журнала; защитный запрет изменений сохранён.")
		}
		cfg = a.Store.Get()
	}
	if stop == cfg.ServiceControl.Stopped {
		if stop {
			return serviceRuntimeOutcome{}
		}
		return fail("SERVICE_RUNTIME_UNCONFIGURED", "Выберите сервис и проверьте подключение. Сохранённого маршрута для включения пока нет.")
	}
	if recoveryStop == nil && a.inactiveServiceRuntime(parent, cfg) {
		if err := parent.Err(); err != nil || a.Store.SetInactiveServiceStop(stop, cfg.Revision) != nil {
			return fail("SERVICE_RUNTIME_CHANGED", "Не удалось сохранить режим. Проверьте актуальные настройки.")
		}
		if !stop {
			a.resumeInactiveAutonomy()
			a.wakeAutonomy()
		}
		return serviceRuntimeOutcome{}
	}
	ctx, cancel := context.WithTimeout(parent, defaultDataplaneApplyTimeout)
	defer cancel()
	current, exists, err := a.Dataplane.Committed()
	if err != nil || !exists || current.State != "committed" || current.Revision != cfg.AppliedRevision {
		return fail("SERVICE_RUNTIME_CHANGED", "Применённое состояние требует проверки. Настройки и ожидающие изменения сохранены.")
	}
	if stop {
		for _, state := range cfg.AppliedServices {
			if state.Enabled && strings.HasPrefix(selectedRoute(state), "xray:node-") && !ordinaryXrayStopPlan(cfg, current) {
				return fail("SERVICE_RUNTIME_CHANGED", "Область применённого Xray маршрута изменилась. Обновите состояние перед остановкой.")
			}
		}
	}
	target := cfg
	if recoveryStop != nil {
		target.SafeMode = false
	}
	target.Revision++
	target.Services = map[string]config.ServiceState{}
	resolved := map[string]string{}
	if stop {
		for _, route := range current.Routes {
			state, ok := cfg.AppliedServices[route.ServiceID]
			if !ok || !state.Enabled || selectedRoute(state) != route.Selected || !sameNodeRecoveryStrings(state.Sources, route.Sources) {
				return fail("SERVICE_RUNTIME_CHANGED", "Область применённого маршрута изменилась. Откройте план перед остановкой.")
			}
			resolved[route.ServiceID] = route.Resolved
		}
		for id, state := range cfg.AppliedServices {
			if state.Enabled && resolved[id] == "" {
				return fail("SERVICE_RUNTIME_CHANGED", "Не все применённые маршруты подтверждены журналом проекта.")
			}
		}
		if len(resolved) == 0 {
			return fail("SERVICE_RUNTIME_UNCONFIGURED", "Выберите сервис и проверьте подключение. Применённых маршрутов пока нет.")
		}
	} else {
		if len(current.Routes) != 0 || len(cfg.AppliedServices) != 0 || len(cfg.ServiceControl.SuspendedRoutes) == 0 {
			return fail("SERVICE_RUNTIME_UNCONFIGURED", "Выберите сервис и проверьте подключение. Сохранённого маршрута для включения пока нет.")
		}
		if !a.suspendedAutonomyScopeCurrent(ctx, cfg) {
			return fail("SERVICE_RUNTIME_CHANGED", "После остановки сервис или его область изменились. Проверьте актуальный список перед включением.")
		}
		for id, state := range cfg.ServiceControl.SuspendedServices {
			target.Services[id] = state
		}
		resolved = cfg.ServiceControl.SuspendedRoutes
		// Refresh only previously applied node+service pairs. No replacement,
		// scope widening or consumption of desired editor changes is authorized.
		profile, profileErr := a.freshNetworkProfile(ctx)
		if profileErr != nil {
			return fail("SERVICE_RUNTIME_CHECK_REQUIRED", "Сеть не подтверждена. Повторите проверку сохранённых подключений.")
		}
		for id, route := range resolved {
			if !strings.HasPrefix(route, "sing-box:node-") {
				continue
			}
			found := false
			for _, service := range a.catalogSnapshot().Services {
				if service.ID != id {
					continue
				}
				found = true
				checkCtx, checkCancel := context.WithTimeout(ctx, time.Minute)
				result, _, checkErr := a.checkAndRecordNode(checkCtx, strings.TrimPrefix(route, "sing-box:"), service, profile, 0)
				checkCancel()
				if checkErr != nil || !result.Available {
					return fail("SERVICE_RUNTIME_CHECK_REQUIRED", "Сохранённое подключение не прошло свежую проверку. Подберите рабочее подключение для сервиса; настройки сохранены.")
				}
			}
			if !found {
				return fail("SERVICE_RUNTIME_CHANGED", "Состав сервисов изменился. Сохранённые настройки требуют просмотра.")
			}
		}
	}
	plan, err := a.buildDataplanePlanWithDNSContext(ctx, target, a.nodeRouteOptions(), changeScopeNode, "", &scopedDNSChange{Suspend: stop, Resume: !stop})
	if err != nil || !plan.Ready {
		// Name the first real reason: a generic "check" hides a refusal the
		// owner can act on (for example a domain service through a VPN).
		message := "План пока не готов. Проверьте сохранённые подключения; ожидающие изменения сохранены."
		if err == nil {
			for _, blocker := range plan.Blockers {
				if blocker.Code == "DOMAIN_FLOW_AUTHORITY_REQUIRED" {
					return fail(serviceRuntimeDomainRoute, blocker.Message+" "+blocker.Resolution)
				}
			}
			if len(plan.Blockers) != 0 {
				message = plan.Blockers[0].Message + " " + plan.Blockers[0].Resolution
			}
		}
		return fail("SERVICE_RUNTIME_CHECK_REQUIRED", message)
	}
	if !stop {
		for _, route := range plan.Routes {
			if resolved[route.ServiceID] != route.Resolved || !sameNodeRecoveryStrings(cfg.ServiceControl.SuspendedServices[route.ServiceID].Sources, route.Sources) {
				return fail("SERVICE_RUNTIME_CHANGED", "Сохранённый маршрут изменился. Новый выбор требует просмотра перед применением.")
			}
		}
		if len(plan.Routes) != len(resolved) {
			return fail("SERVICE_RUNTIME_CHANGED", "Состав сохранённых сервисов изменился.")
		}
	}
	if recoveryStop != nil && (len(plan.Routes) != 0 || len(plan.Adapters) != 0 || plan.LAN != nil || plan.DNS != nil || plan.SafeMode || !plan.Ready) {
		return fail("DATAPLANE_RECOVERY_REQUIRED", "План остановки не должен создавать новые маршруты или правила DNS.")
	}
	binding, err := a.bindApplyReview(ctx, cfg, plan, changeScopeNode, "")
	if err != nil {
		return fail("SERVICE_RUNTIME_CHANGED", "Настройки или сеть изменились. Повторите действие.")
	}
	ctx = dataplane.WithReviewGuard(ctx, func(ctx context.Context) error {
		if err := binding.guard(a, ctx); err != nil {
			return err
		}
		if recoveryStop != nil {
			if err := recoveryStop.check(ctx, false); err != nil {
				return err
			}
		}
		latest, ok, err := a.Dataplane.Committed()
		if err != nil || !ok || !reflect.DeepEqual(latest, current) {
			return dataplane.ErrReviewChanged
		}
		return nil
	})
	if stop && current.DNS != nil {
		if err := a.observeCommittedRuntime(ctx, current); err != nil {
			if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
				return fail("SERVICE_RUNTIME_CHANGED", "Проверка состояния не завершена. Повторите выключение.")
			}
			if err := a.Dataplane.PrepareDNSRecovery(ctx, current); err != nil {
				if !errors.Is(err, dataplane.ErrReviewChanged) {
					a.Operations.FenceJournal()
				}
				return fail("SERVICE_RUNTIME_FAILED", "Не удалось завершить очистку DNS. Откройте журнал; настройки сохранены.")
			}
		}
	}
	execution, err := a.applyDataplane(ctx, plan, func() (func() error, error) {
		if err := binding.guard(a, ctx); err != nil {
			return nil, err
		}
		var undo func() error
		var err error
		if recoveryStop != nil {
			if err = recoveryStop.check(ctx, true); err != nil {
				return nil, err
			}
			undo, err = a.Store.CommitServiceRecoveryStop(cfg, resolved)
		} else {
			undo, err = a.Store.CommitServiceRuntime(stop, resolved, cfg.Revision)
		}
		if errors.Is(err, config.ErrRevisionChanged) {
			return nil, dataplane.ErrReviewChanged
		}
		if err == nil {
			binding.cfg = a.Store.Get()
		}
		return undo, err
	})
	if err != nil {
		failure := classifyApplyExecutionFailure(err.Error(), execution.State)
		return serviceRuntimeOutcome{Code: "SERVICE_RUNTIME_FAILED", Message: failure.Message, Failure: &failure, Execution: &execution}
	}
	a.wakeReconciler()
	return serviceRuntimeOutcome{LiveApplied: true, Execution: &execution}
}

func (a *App) suspendedAutonomyScopeCurrent(ctx context.Context, cfg config.Config) bool {
	if a.loadAutonomy(ctx) != nil {
		return false
	}
	a.autonomy.mu.Lock()
	defer a.autonomy.mu.Unlock()
	for id, state := range cfg.ServiceControl.SuspendedServices {
		if !state.Enabled {
			continue
		}
		s := a.autonomy.doc.Services[id]
		if !cfg.Services[id].Enabled || s.Removing || s.Enabled && (autonomyScopeRefusal(cfg, s) != "" || !sameNodeRecoveryStrings(state.Sources, s.Sources)) {
			return false
		}
	}
	return true
}

func (a *App) resumeInactiveAutonomy() {
	a.autonomy.mu.Lock()
	defer a.autonomy.mu.Unlock()
	if !a.autonomy.loaded || a.autonomy.blocked || !a.autonomy.doc.Policy.Enabled {
		return
	}
	changed := false
	for id, s := range a.autonomy.doc.Services {
		r := a.autonomy.doc.Runtime[id]
		// Preserve actual search cooldowns and failures. A canceled or
		// interrupted check may start once with current scope after Resume.
		if s.Enabled && !s.Removing && (r.State == "paused" || r.State == "checking" || r.State == "unconfirmed" && r.Failures == 0) && !r.NextCheck.IsZero() {
			r.NextCheck = time.Time{}
			a.autonomy.doc.Runtime[id] = r
			changed = true
		}
	}
	if changed {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = a.persistAutonomyLocked(ctx)
	}
}

// Pending checks may be stopped even before the first Apply. Only an empty
// applied state and a settled journal allow this settings-only transition.
func (a *App) inactiveServiceRuntime(ctx context.Context, cfg config.Config) bool {
	if a.Dataplane == nil || a.Dataplane.StateRoot == "" || cfg.SafeMode || cfg.HasEnabledAppliedServices() || len(cfg.ServiceControl.SuspendedServices)+len(cfg.ServiceControl.SuspendedRoutes) != 0 {
		return false
	}
	if a.PendingSelfUpdateRecovery() || a.PendingComponentRecovery() || a.bootRecoveryPending() != nil || a.Dataplane.CheckExecutionRecovery(ctx) != nil {
		return false
	}
	plan, exists, err := a.Dataplane.Committed()
	if err != nil {
		return false
	}
	if !exists {
		return cfg.AppliedRevision == 0 && cfg.AppliedNetworkPolicy == nil
	}
	return plan.State == "committed" && plan.Revision == cfg.AppliedRevision && plan.Noop &&
		len(plan.Routes)+len(plan.Adapters)+len(plan.RetiringAdapters) == 0 && plan.LAN == nil && plan.DNS == nil &&
		plan.DomainPolicy == nil && plan.SyntheticDNS == nil && !plan.SuspendDNS && !plan.DiscardDNS
}
