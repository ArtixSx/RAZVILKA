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
	}
	if !decodeServiceControl(w, r, &request) {
		return
	}
	if request.Action != "stop" && request.Action != "resume" || request.Action == "stop" && request.Confirm != "STOP_OWNED_ROUTES" || request.Action == "resume" && request.Confirm != "RESUME_OWNED_ROUTES" {
		http.Error(w, "Подтвердите включение или остановку маршрутов проекта.", http.StatusBadRequest)
		return
	}
	fail := func(code, message string) {
		writeJSON(w, http.StatusConflict, map[string]any{"ok": false, "code": code, "error": message, "live_applied": false})
	}
	if a.Store == nil || a.Dataplane == nil {
		fail("SERVICE_RUNTIME_UNAVAILABLE", "Управление маршрутами недоступно.")
		return
	}
	cfg := a.Store.Get()
	if cfg.Revision != request.ExpectedRevision {
		fail("SERVICE_CONTROL_CHANGED", "Настройки изменились. Обновите состояние и повторите действие.")
		return
	}
	if cfg.SafeMode {
		fail("SERVICE_RUNTIME_SAFE_MODE", "Безопасный режим запрещает изменение маршрутов. Проверьте настройки безопасности.")
		return
	}
	stop := request.Action == "stop"
	if stop == cfg.ServiceControl.Stopped {
		if stop {
			writeJSON(w, http.StatusOK, map[string]any{"ok": true, "live_applied": false, "control": a.serviceControlView()})
			return
		}
		fail("SERVICE_RUNTIME_UNCONFIGURED", "Выберите сервис и проверьте подключение. Сохранённого маршрута для включения пока нет.")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), defaultDataplaneApplyTimeout)
	defer cancel()
	current, exists, err := a.Dataplane.Committed()
	if err != nil || !exists || current.State != "committed" || current.Revision != cfg.AppliedRevision {
		fail("SERVICE_RUNTIME_CHANGED", "Применённое состояние требует проверки. Настройки и ожидающие изменения сохранены.")
		return
	}
	target := cfg
	target.Revision++
	target.Services = map[string]config.ServiceState{}
	resolved := map[string]string{}
	if stop {
		for _, route := range current.Routes {
			state, ok := cfg.AppliedServices[route.ServiceID]
			if !ok || !state.Enabled || selectedRoute(state) != route.Selected || !sameNodeRecoveryStrings(state.Sources, route.Sources) {
				fail("SERVICE_RUNTIME_CHANGED", "Область применённого маршрута изменилась. Откройте план перед остановкой.")
				return
			}
			resolved[route.ServiceID] = route.Resolved
		}
		for id, state := range cfg.AppliedServices {
			if state.Enabled && resolved[id] == "" {
				fail("SERVICE_RUNTIME_CHANGED", "Не все применённые маршруты подтверждены журналом проекта.")
				return
			}
		}
		if len(resolved) == 0 {
			fail("SERVICE_RUNTIME_UNCONFIGURED", "Выберите сервис и проверьте подключение. Применённых маршрутов пока нет.")
			return
		}
	} else {
		if len(current.Routes) != 0 || len(cfg.AppliedServices) != 0 || len(cfg.ServiceControl.SuspendedRoutes) == 0 {
			fail("SERVICE_RUNTIME_UNCONFIGURED", "Выберите сервис и проверьте подключение. Сохранённого маршрута для включения пока нет.")
			return
		}
		for id, state := range cfg.ServiceControl.SuspendedServices {
			target.Services[id] = state
		}
		resolved = cfg.ServiceControl.SuspendedRoutes
		// Refresh only previously applied node+service pairs. No replacement,
		// scope widening or consumption of desired editor changes is authorized.
		profile, profileErr := a.freshNetworkProfile(ctx)
		if profileErr != nil {
			fail("SERVICE_RUNTIME_CHECK_REQUIRED", "Сеть не подтверждена. Повторите проверку сохранённых подключений.")
			return
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
					fail("SERVICE_RUNTIME_CHECK_REQUIRED", "Сохранённое подключение не прошло свежую проверку. Подберите рабочее подключение для сервиса; настройки сохранены.")
					return
				}
			}
			if !found {
				fail("SERVICE_RUNTIME_CHANGED", "Состав сервисов изменился. Сохранённые настройки требуют просмотра.")
				return
			}
		}
	}
	plan, err := a.buildDataplanePlanForScope(target, a.nodeRouteOptions(), changeScopeNode, "")
	if err != nil || !plan.Ready {
		fail("SERVICE_RUNTIME_CHECK_REQUIRED", "План пока не готов. Проверьте сохранённые подключения; ожидающие изменения сохранены.")
		return
	}
	if !stop {
		for _, route := range plan.Routes {
			if resolved[route.ServiceID] != route.Resolved || !sameNodeRecoveryStrings(cfg.ServiceControl.SuspendedServices[route.ServiceID].Sources, route.Sources) {
				fail("SERVICE_RUNTIME_CHANGED", "Сохранённый маршрут изменился. Новый выбор требует просмотра перед применением.")
				return
			}
		}
		if len(plan.Routes) != len(resolved) {
			fail("SERVICE_RUNTIME_CHANGED", "Состав сохранённых сервисов изменился.")
			return
		}
	}
	binding, err := a.bindApplyReview(ctx, cfg, plan, changeScopeNode, "")
	if err != nil {
		fail("SERVICE_RUNTIME_CHANGED", "Настройки или сеть изменились. Повторите действие.")
		return
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
		writeJSON(w, http.StatusConflict, map[string]any{"ok": false, "code": "SERVICE_RUNTIME_FAILED", "error": failure.Message, "failure": failure, "execution": execution, "live_applied": false})
		return
	}
	a.wakeReconciler()
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "live_applied": true, "execution": execution, "control": a.serviceControlView()})
}
