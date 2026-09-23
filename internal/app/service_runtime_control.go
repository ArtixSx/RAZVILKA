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
)

// Runtime control uses the existing transaction manager and adapter ownership
// checks. It never calls system service stop/restart commands.
func (a *App) serviceControlRuntime(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	var request struct {
		ExpectedRevision uint64 `json:"expected_revision"`
		Action           string `json:"action"`
		Confirm          string `json:"confirm"`
		IdempotencyKey   string `json:"idempotency_key,omitempty"`
	}
	if !decodeServiceControl(w, r, &request) {
		return
	}
	if request.Action != "stop" && request.Action != "resume" || request.Action == "stop" && request.Confirm != "STOP_OWNED_ROUTES" || request.Action == "resume" && request.Confirm != "RESUME_OWNED_ROUTES" {
		http.Error(w, "Подтвердите включение или остановку маршрутов проекта.", http.StatusBadRequest)
		return
	}
	if request.IdempotencyKey != "" {
		job, err := a.enqueueDurableServiceJob(r.Context(), serviceControlJobRequest{Kind: request.Action, ExpectedRevision: &request.ExpectedRevision, IdempotencyKey: request.IdempotencyKey})
		if err != nil {
			a.writeDurableJobFailure(w, err)
			return
		}
		writeJSON(w, http.StatusAccepted, map[string]any{"job": job.presentation(), "persistent": true})
		return
	}
	// Older clients keep the synchronous contract; production UI sends a key.
	release, err := a.Operations.Exclusive(r.Context())
	if err != nil {
		a.writeOperationFailure(w, err)
		return
	}
	defer release()
	outcome := a.executeServiceRuntime(r.Context(), request.Action, request.ExpectedRevision)
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
	if cfg.SafeMode {
		return fail("SERVICE_RUNTIME_SAFE_MODE", "Безопасный режим запрещает изменение маршрутов. Проверьте настройки безопасности.")
	}
	stop := action == "stop"
	if stop == cfg.ServiceControl.Stopped {
		if stop {
			return serviceRuntimeOutcome{}
		}
		return fail("SERVICE_RUNTIME_UNCONFIGURED", "Выберите сервис и проверьте подключение. Сохранённого маршрута для включения пока нет.")
	}
	ctx, cancel := context.WithTimeout(parent, defaultDataplaneApplyTimeout)
	defer cancel()
	current, exists, err := a.Dataplane.Committed()
	if err != nil || !exists || current.State != "committed" || current.Revision != cfg.AppliedRevision {
		return fail("SERVICE_RUNTIME_CHANGED", "Применённое состояние требует проверки. Настройки и ожидающие изменения сохранены.")
	}
	target := cfg
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
	plan, err := a.buildDataplanePlanForScope(target, a.nodeRouteOptions(), changeScopeNode, "")
	if err != nil || !plan.Ready {
		return fail("SERVICE_RUNTIME_CHECK_REQUIRED", "План пока не готов. Проверьте сохранённые подключения; ожидающие изменения сохранены.")
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
	binding, err := a.bindApplyReview(ctx, cfg, plan, changeScopeNode, "")
	if err != nil {
		return fail("SERVICE_RUNTIME_CHANGED", "Настройки или сеть изменились. Повторите действие.")
	}
	ctx = dataplane.WithReviewGuard(ctx, func(ctx context.Context) error {
		if err := binding.guard(a, ctx); err != nil {
			return err
		}
		latest, ok, err := a.Dataplane.Committed()
		if err != nil || !ok || !reflect.DeepEqual(latest, current) {
			return dataplane.ErrReviewChanged
		}
		return nil
	})
	execution, err := a.Dataplane.Apply(ctx, plan, func() (func() error, error) {
		if err := binding.guard(a, ctx); err != nil {
			return nil, err
		}
		undo, err := a.Store.CommitServiceRuntime(stop, resolved, cfg.Revision)
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
