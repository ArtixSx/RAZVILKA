package app

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"reflect"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/evidence"
	"github.com/ArtixSx/razvilka/internal/nodestore"
	"github.com/ArtixSx/razvilka/internal/operationgate"
	"github.com/ArtixSx/razvilka/internal/testlab"
)

type serviceControlResult struct {
	ServiceFingerprint string        `json:"-"`
	Kind               string        `json:"kind"`
	ServiceID          string        `json:"service_id"`
	Status             string        `json:"status"`
	Available          bool          `json:"available"`
	LatencyMS          int64         `json:"latency_ms,omitempty"`
	CheckedAt          time.Time     `json:"checked_at"`
	ValidUntil         time.Time     `json:"valid_until"`
	ConfigRevision     uint64        `json:"config_revision"`
	Stale              bool          `json:"stale"`
	FreshnessVerified  bool          `json:"freshness_verified"`
	CheckedRoute       string        `json:"checked_route"`
	LatencyKind        string        `json:"latency_kind"`
	NetworkProfile     string        `json:"network_profile"`
	AppliedRoute       string        `json:"applied_route"`
	RecommendedNodeID  string        `json:"recommended_node_id,omitempty"`
	Scope              nodeScopeView `json:"scope"`
	ScopeRequired      bool          `json:"scope_required"`
	Message            string        `json:"message"`
}

type serviceControlJobRequest struct {
	IdempotencyKey   string             `json:"idempotency_key,omitempty"`
	ExpectedRevision *uint64            `json:"expected_revision,omitempty"`
	Kind             string             `json:"kind"`
	ServiceIDs       []string           `json:"service_ids"`
	NodeIDs          []string           `json:"node_ids,omitempty"`
	DNS              *serviceDNSJobSpec `json:"dns,omitempty"`
	NodeApply        *nodeApplyJobSpec  `json:"node_apply,omitempty"`
	NodeCheckMode    string             `json:"node_check_mode,omitempty"`
	nodeReviewToken  string
	nodeReviewOwner  [32]byte
	durableID        uint64
	intentHash       string
	durableCursor    int
}

func (a *App) serviceControlMemory() map[string]any {
	view := a.nodeCheckSnapshot()
	a.nodeChecks.mu.Lock()
	results := make([]serviceControlResult, 0, len(a.nodeChecks.serviceResults))
	for _, result := range a.nodeChecks.serviceResults {
		result.Scope.Sources = slices.Clone(result.Scope.Sources)
		result.Stale = !time.Now().Before(result.ValidUntil)
		result.FreshnessVerified = false
		results = append(results, result)
	}
	a.nodeChecks.mu.Unlock()
	sort.Slice(results, func(i, j int) bool { return results[i].ServiceID < results[j].ServiceID })
	view["results"] = results
	a.addDurableServiceJobs(view)
	return view
}

func (a *App) serviceControlView(ctx context.Context) map[string]any {
	cfg := a.Store.Get()
	c := cfg.ServiceControl
	view := a.serviceControlMemory()
	freshnessCtx, stopFreshness := context.WithTimeout(ctx, 3*time.Second)
	profile, profileErr := a.freshNetworkProfile(freshnessCtx)
	stopFreshness()
	serviceHashes := map[string]string{}
	for _, service := range a.catalogSnapshot().Services {
		serviceHashes[service.ID] = applyReviewHash(service)
	}
	for i, result := range view["results"].([]serviceControlResult) {
		result.FreshnessVerified = true
		result.Stale = result.Stale || profileErr != nil || profile != result.NetworkProfile || result.ConfigRevision != cfg.Revision || serviceHashes[result.ServiceID] != result.ServiceFingerprint
		view["results"].([]serviceControlResult)[i] = result
	}
	state := "unconfigured"
	canStop := false
	var runtimeErr error
	if c.Stopped {
		state = "stopped"
	} else {
		for _, applied := range cfg.AppliedServices {
			if applied.Enabled {
				state = "unknown"
				runtimeErr = dataplane.ErrReviewChanged
				break
			}
		}
		if state == "unknown" && a.Dataplane != nil {
			if committed, ok, err := a.Dataplane.Committed(); err == nil && ok && committed.State == "committed" && committed.Revision == cfg.AppliedRevision && len(committed.Routes) > 0 {
				canStop = true
				// Result freshness and actual owned runtime each have their own
				// bounded observation. A slow WAN sample must not spend the
				// runtime's inspection budget; caller cancellation still applies.
				runtimeErr = a.Dataplane.ObserveCommittedRuntime(ctx, committed)
				if runtimeErr == nil {
					state = "running"
				}
			}
		}
	}
	next := time.Time{}
	a.reconciler.mu.Lock()
	for _, op := range a.reconciler.doc.Operations {
		if op.Kind == "service-checks" {
			next = op.NextRun
		}
	}
	a.reconciler.mu.Unlock()
	interval := c.Schedule.IntervalSeconds
	if interval == 0 {
		interval = 300
	}
	view["config_revision"], view["mode"] = cfg.Revision, c.EffectiveMode()
	view["runtime_state"], view["running"] = state, state == "running"
	view["can_stop"] = canStop
	if state == "unknown" {
		view["runtime_issue"] = serviceRuntimeIssue(runtimeErr)
	}
	view["resume_available"], view["safe_mode"] = c.Stopped && len(c.SuspendedRoutes) > 0, cfg.SafeMode
	view["schedule"] = map[string]any{"enabled": c.Schedule.Enabled, "interval_seconds": interval, "service_ids": append([]string{}, c.Schedule.ServiceIDs...), "next_check_at": next}
	view["notice"] = "Автопилот использует только разрешённые правила сервисов. Ручной режим останавливает автоматическую замену; проверки по таймеру продолжаются."
	return view
}

func serviceRuntimeIssue(err error) map[string]string {
	code, message := "UNAVAILABLE", "Не удалось подтвердить процессы и правила маршрутов. Повторите проверку состояния."
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		code, message = "TIMEOUT", "Проверка состояния не завершилась вовремя. Работа обхода пока не подтверждена; повторите проверку."
	case errors.Is(err, context.Canceled):
		code, message = "CANCELED", "Проверка состояния отменена. Повторите проверку."
	case errors.Is(err, dataplane.ErrNetworkChanged):
		code, message = "NETWORK_CHANGED", "Сеть изменилась или временно недоступна. Нужна свежая проверка маршрута."
	case errors.Is(err, dataplane.ErrReviewChanged):
		code, message = "CONFIGURATION_CHANGED", "Текущие настройки и применённые маршруты не совпадают. Обновите состояние."
	}
	// Never expose raw command output: it can contain private route addresses.
	return map[string]string{"code": code, "message": message}
}

func (a *App) serviceControl(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if a.Store == nil {
		http.Error(w, "Настройки недоступны.", http.StatusServiceUnavailable)
		return
	}
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, a.serviceControlView(r.Context()))
	case http.MethodPut:
		var request struct {
			ExpectedRevision uint64                       `json:"expected_revision"`
			Mode             *string                      `json:"mode,omitempty"`
			Schedule         *config.ServiceCheckSchedule `json:"schedule,omitempty"`
			Confirm          string                       `json:"confirm"`
		}
		if !decodeServiceControl(w, r, &request) {
			return
		}
		if request.Confirm != "SAVE_SERVICE_CONTROL" || request.Mode == nil && request.Schedule == nil || request.Mode != nil && *request.Mode != "auto" && *request.Mode != "manual" {
			http.Error(w, "Проверьте режим и параметры таймера.", http.StatusBadRequest)
			return
		}
		if request.Schedule != nil {
			for _, id := range request.Schedule.ServiceIDs {
				if !a.hasService(id) {
					http.Error(w, "В таймере указан неизвестный сервис.", http.StatusBadRequest)
					return
				}
			}
		}
		if err := a.Store.UpdateServiceControl(request.Mode, request.Schedule, request.ExpectedRevision); err != nil {
			status := http.StatusBadRequest
			if errors.Is(err, config.ErrRevisionChanged) {
				status = http.StatusConflict
			}
			writeJSON(w, status, map[string]any{"ok": false, "code": "SERVICE_CONTROL_CHANGED", "error": "Настройки изменились или параметры недопустимы. Обновите страницу.", "live_applied": false})
			return
		}
		a.wakeReconciler()
		writeJSON(w, http.StatusOK, a.serviceControlView(r.Context()))
	default:
		methodNotAllowed(w)
	}
}

func decodeServiceControl(w http.ResponseWriter, r *http.Request, value any) bool {
	d := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10))
	d.DisallowUnknownFields()
	if d.Decode(value) != nil || d.Decode(&struct{}{}) != io.EOF {
		http.Error(w, "Некорректный запрос.", http.StatusBadRequest)
		return false
	}
	return true
}

func (a *App) serviceControlCurrent(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method == http.MethodDelete {
		id, err := strconv.ParseUint(r.URL.Query().Get("job_id"), 10, 64)
		if err != nil || id == 0 {
			http.Error(w, "Укажите номер отменяемой проверки.", http.StatusBadRequest)
			return
		}
		if handled, err := a.cancelDurableServiceJob(r.Context(), id); handled {
			if err != nil {
				a.writeDurableJobFailure(w, err)
				return
			}
			writeJSON(w, http.StatusOK, a.serviceControlMemory())
			return
		}
		a.nodeChecks.mu.Lock()
		if a.nodeChecks.job == nil || a.nodeChecks.job.ID != id {
			a.nodeChecks.mu.Unlock()
			writeJSON(w, http.StatusConflict, map[string]any{"ok": false, "code": "SERVICE_JOB_CHANGED", "error": "Текущая проверка уже изменилась. Обновите состояние."})
			return
		}
		if a.nodeChecks.cancel != nil && a.nodeChecks.job != nil && strings.HasPrefix(a.nodeChecks.job.Mode, "service-") {
			a.nodeChecks.job.State, a.nodeChecks.job.Message = "canceling", "Завершаем проверку и очищаем временные ресурсы."
			a.nodeChecks.cancel()
		}
		a.nodeChecks.mu.Unlock()
	} else if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	writeJSON(w, http.StatusOK, a.serviceControlMemory())
}

func (a *App) serviceControlJobs(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	var request serviceControlJobRequest
	if !decodeServiceControl(w, r, &request) {
		return
	}
	if request.ExpectedRevision == nil {
		http.Error(w, "Обновите список сервисов перед проверкой.", http.StatusBadRequest)
		return
	}
	if request.Kind != "check" && request.Kind != "select" {
		http.Error(w, "Выберите проверку или подбор подключения.", http.StatusBadRequest)
		return
	}
	if request.IdempotencyKey != "" {
		job, err := a.enqueueDurableServiceJob(r.Context(), request)
		if err != nil {
			a.writeDurableJobFailure(w, err)
			return
		}
		writeJSON(w, http.StatusAccepted, map[string]any{"job": job.presentation(), "persistent": true})
		return
	}
	if _, err := a.startServiceControlJob(r.Context(), request, false); err != nil {
		if errors.Is(err, errServiceControlRequest) {
			http.Error(w, "Выберите до 64 сервисов для проверки или до 12 для подбора и не более 3 доступных узлов.", http.StatusBadRequest)
		} else if errors.Is(err, config.ErrRevisionChanged) {
			writeJSON(w, http.StatusConflict, map[string]any{"code": "SERVICE_CONTROL_CHANGED", "error": "Настройки изменились. Обновите состояние перед проверкой."})
		} else {
			a.writeOperationFailure(w, err)
		}
		return
	}
	writeJSON(w, http.StatusAccepted, a.serviceControlMemory())
}

var errServiceControlRequest = errors.New("invalid service control request")

// Shares the existing exact-check lifetime, one job slot and exclusive lease.
// Scheduled jobs also use this path; there is no second queue or checker.
func (a *App) startServiceControlJob(ctx context.Context, request serviceControlJobRequest, scheduled bool) (<-chan struct{}, error) {
	if a.Store == nil || len(request.ServiceIDs) == 0 || len(request.ServiceIDs) > config.MaxScheduledServices || request.Kind == "select" && len(request.ServiceIDs) > 12 || len(request.NodeIDs) > 3 || request.Kind != "check" && request.Kind != "select" || request.Kind == "check" && len(request.NodeIDs) != 0 {
		return nil, errServiceControlRequest
	}
	release, err := a.Operations.Exclusive(ctx)
	if err != nil {
		return nil, err
	}
	retained := false
	defer func() {
		if !retained {
			release()
		}
	}()
	cat := a.catalogSnapshot()
	services := make([]catalog.Service, 0, len(request.ServiceIDs))
	seen := map[string]bool{}
	for _, id := range request.ServiceIDs {
		if seen[id] {
			return nil, errServiceControlRequest
		}
		seen[id] = true
		found := false
		for _, service := range cat.Services {
			if service.ID == id {
				services = append(services, service)
				found = true
				break
			}
		}
		if !found {
			return nil, errServiceControlRequest
		}
	}
	cfg := a.Store.Get()
	if request.intentHash != "" && request.intentHash != durableServiceIntentHash(cfg, services) {
		return nil, config.ErrRevisionChanged
	}
	if request.ExpectedRevision != nil && cfg.Revision != *request.ExpectedRevision {
		return nil, config.ErrRevisionChanged
	}
	if scheduled && (!cfg.ServiceControl.Schedule.Enabled || cfg.ServiceControl.Stopped || !slices.Equal(cfg.ServiceControl.Schedule.ServiceIDs, request.ServiceIDs)) {
		return nil, errServiceControlRequest
	}
	snapshot := nodestore.Snapshot{}
	if a.Nodes != nil {
		snapshot, err = a.Nodes.Snapshot(ctx, time.Now())
		if err != nil {
			return nil, err
		}
	}
	if request.Kind == "select" {
		if a.Nodes == nil || a.NodeChecker == nil {
			return nil, errServiceControlRequest
		}
		seen = map[string]bool{}
		for _, id := range request.NodeIDs {
			if seen[id] {
				return nil, errServiceControlRequest
			}
			seen[id] = true
			found := false
			for _, node := range snapshot.Nodes {
				if node.ID == id && !node.Disabled && node.State != "expired" {
					found = true
				}
			}
			if !found {
				return nil, errServiceControlRequest
			}
		}
	}
	resolved := map[string]string{}
	if cfg.ServiceControl.Stopped {
		for id, route := range cfg.ServiceControl.SuspendedRoutes {
			resolved[id] = route
		}
	} else if a.Dataplane != nil {
		if plan, exists, err := a.Dataplane.Committed(); err == nil && exists && plan.Revision == cfg.AppliedRevision {
			for _, route := range plan.Routes {
				resolved[route.ServiceID] = route.Resolved
			}
		}
	}
	a.nodeChecks.mu.Lock()
	if a.nodeChecks.closed || a.nodeChecks.root == nil || a.nodeChecks.root.Err() != nil {
		a.nodeChecks.mu.Unlock()
		return nil, context.Canceled
	}
	if a.nodeChecks.cancel != nil {
		a.nodeChecks.mu.Unlock()
		return nil, operationgate.ErrBusy
	}
	parent := a.nodeChecks.root
	if scheduled || request.durableID != 0 {
		parent = ctx
	}
	budget := 5 * time.Minute
	if request.Kind == "check" {
		budget = time.Duration(len(services))*time.Minute + time.Minute
	}
	jobCtx, cancel := context.WithTimeout(parent, budget)
	a.nodeChecks.nextID++
	id := a.nodeChecks.nextID
	if request.durableID != 0 {
		id = request.durableID
	}
	a.nodeChecks.job = &nodeCheckJob{ID: id, Mode: "service-" + request.Kind, State: "running", Total: len(services), Completed: request.durableCursor, StartedAt: time.Now().UTC(), Message: "Проверяем выбранные сервисы. Маршруты сохраняются.", Results: []nodeCheckItem{}, ServiceResults: []serviceControlResult{}}
	a.nodeChecks.cancel = cancel
	done := make(chan struct{})
	a.nodeChecks.done = done
	a.nodeChecks.mu.Unlock()
	retained = true
	go a.runServiceControlJob(jobCtx, cancel, done, release, id, request, services, cfg, resolved, snapshot)
	return done, nil
}

func (a *App) runServiceControlJob(ctx context.Context, cancel context.CancelFunc, done chan struct{}, release func(), id uint64, request serviceControlJobRequest, services []catalog.Service, cfg config.Config, resolved map[string]string, snapshot nodestore.Snapshot) {
	defer close(done)
	defer release()
	defer cancel()
	profile, err := a.freshNetworkProfile(ctx)
	catHash := applyReviewHash(a.catalogSnapshot())
	for _, service := range services[request.durableCursor:] {
		if err != nil || ctx.Err() != nil {
			break
		}
		if !reflect.DeepEqual(cfg, a.Store.Get()) || catHash != applyReviewHash(a.catalogSnapshot()) {
			err = dataplane.ErrReviewChanged
			break
		}
		applied, present := cfg.AppliedServices[service.ID]
		if cfg.ServiceControl.Stopped {
			applied, present = cfg.ServiceControl.SuspendedServices[service.ID]
		}
		result := serviceControlResult{Kind: request.Kind, ServiceID: service.ID, Status: "not-ready", ConfigRevision: cfg.Revision, NetworkProfile: profile, AppliedRoute: resolved[service.ID], CheckedRoute: resolved[service.ID], LatencyKind: "service_check", Scope: nodeScopePresentation(applied.Sources), ScopeRequired: !present || !applied.Enabled, Message: "Для сервиса пока нет подтверждённого маршрута."}
		result.ServiceFingerprint = applyReviewHash(service)
		if cfg.ServiceControl.Stopped {
			result.AppliedRoute = ""
		}
		if !present {
			result.Scope = nodeScopeView{Mode: "unknown", Sources: []string{}, Summary: "Устройства ещё не выбраны"}
		}
		if request.Kind == "select" {
			candidates := a.serviceCandidates(snapshot, request.NodeIDs, resolved[service.ID], service.ID, profile, time.Now())
			result.Status, result.Message = "inconclusive", "В выбранной ограниченной выборке рабочее подключение не подтверждено."
			for _, nodeID := range candidates {
				if ctx.Err() != nil {
					break
				}
				a.recordServiceAttempt(service.ID, profile, nodeID, time.Now())
				checkCtx, stop := context.WithTimeout(ctx, time.Minute)
				check, latest, checkErr := a.checkAndRecordNode(checkCtx, nodeID, service, profile, snapshot.Generation)
				stop()
				if checkErr == nil {
					snapshot = latest
				}
				if checkErr == nil && check.Available {
					result.Available, result.Status, result.LatencyMS, result.RecommendedNodeID = true, "pass", check.LatencyMS, nodeID
					result.CheckedRoute = "sing-box:" + nodeID
					result.ValidUntil = check.ExpiresAt
					result.Message = "Подключение прошло проверку сервиса. Просмотрите маршрут и выберите устройства перед применением."
					break
				}
				if errors.Is(checkErr, dataplane.ErrReviewChanged) || errors.Is(checkErr, dataplane.ErrExactNodeNetworkChanged) {
					err = checkErr
					break
				}
			}
		} else if strings.HasPrefix(result.CheckedRoute, "sing-box:node-") {
			checkCtx, stop := context.WithTimeout(ctx, time.Minute)
			check, latest, checkErr := a.checkAndRecordNode(checkCtx, strings.TrimPrefix(result.CheckedRoute, "sing-box:"), service, profile, snapshot.Generation)
			stop()
			if checkErr == nil {
				snapshot = latest
				result.Available, result.LatencyMS, result.Message = check.Available, check.LatencyMS, check.Message
				result.ValidUntil = check.ExpiresAt
				result.Status = "inconclusive"
				if check.Available {
					result.Status = "pass"
					if result.AppliedRoute != "" {
						if plan, exists, planErr := a.Dataplane.Committed(); planErr != nil || !exists || a.Dataplane.CheckCommittedNodeHealth(ctx, plan) != nil {
							result.Status, result.Available = "inconclusive", false
							result.Message = "Сам узел отвечает, но работа применённого маршрута проекта не подтверждена."
						}
					} else {
						result.Message = "Сохранённый узел прошёл проверку. Маршруты проекта остаются остановленными."
					}
				} else if check.Verdict == evidence.VerdictBlocked || check.Verdict == evidence.VerdictMisrouted {
					result.Status = "fail"
				}
			} else {
				result.Status, result.Message = "inconclusive", nodeCheckFailureMessage(checkErr)
			}
		} else {
			a.checkServiceRoute(ctx, service, profile, &result)
		}
		current, networkErr := a.freshNetworkProfile(ctx)
		if ctx.Err() != nil || networkErr != nil || current != profile || !reflect.DeepEqual(cfg, a.Store.Get()) || catHash != applyReviewHash(a.catalogSnapshot()) || err != nil {
			result.Status, result.Available, result.RecommendedNodeID, result.LatencyMS = "inconclusive", false, "", 0
			result.Message = "Проверка отменена либо изменились сеть или настройки. Повторите её."
			err = dataplane.ErrReviewChanged
		}
		result.CheckedAt = time.Now().UTC()
		if result.ValidUntil.IsZero() || result.ValidUntil.After(result.CheckedAt.Add(2*time.Minute)) {
			result.ValidUntil = result.CheckedAt.Add(2 * time.Minute)
		}
		a.nodeChecks.mu.Lock()
		if a.nodeChecks.job != nil && a.nodeChecks.job.ID == id {
			a.nodeChecks.job.Completed++
			a.nodeChecks.job.ServiceResults = append(a.nodeChecks.job.ServiceResults, result)
			if a.nodeChecks.serviceResults == nil {
				a.nodeChecks.serviceResults = map[string]serviceControlResult{}
			}
			if len(a.nodeChecks.serviceResults) >= 128 {
				oldest := ""
				for id, value := range a.nodeChecks.serviceResults {
					if oldest == "" || value.CheckedAt.Before(a.nodeChecks.serviceResults[oldest].CheckedAt) {
						oldest = id
					}
				}
				delete(a.nodeChecks.serviceResults, oldest)
			}
			a.nodeChecks.serviceResults[result.ServiceID] = result
		}
		a.nodeChecks.mu.Unlock()
		if request.durableID != 0 {
			break // One service per durable dispatch; repair gets the next turn.
		}
	}
	// Every checker/prober has returned and joined cleanup. Publish terminal
	// state only after releasing admission, so its follow-up GET can read stores.
	release()
	a.nodeChecks.mu.Lock()
	if a.nodeChecks.job != nil && a.nodeChecks.job.ID == id {
		job := a.nodeChecks.job
		finished := time.Now().UTC()
		job.FinishedAt = &finished
		job.State, job.Message = "completed", "Проверка завершена. Маршруты не изменялись."
		if ctx.Err() != nil {
			job.State, job.Message = "canceled", "Проверка остановлена; временные ресурсы очищены."
		} else if err != nil {
			job.State, job.Message = "failed", "Сеть или настройки изменились. Повторите проверку."
		} else if request.durableID != 0 && job.Completed < job.Total {
			job.State, job.Phase, job.FinishedAt = "queued", "waiting", nil
			job.Message = "Часть сервисов проверена. Продолжим после приоритетных задач."
		}
		a.nodeChecks.cancel = nil
	}
	a.nodeChecks.mu.Unlock()
}

func (a *App) serviceCandidates(snapshot nodestore.Snapshot, requested []string, current, serviceID, profile string, now time.Time) []string {
	eligible := map[string]bool{}
	type priority struct {
		rank      int
		attempted time.Time
	}
	priorities := map[string]priority{}
	a.nodeChecks.mu.Lock()
	defer a.nodeChecks.mu.Unlock()
	for _, n := range snapshot.Nodes {
		if !n.Disabled && n.State != "expired" {
			eligible[n.ID] = true
			p := priority{rank: 1}
			for _, check := range n.Health.History {
				if check.ServiceID != serviceID || check.NetworkProfile != profile || check.RoutePathID != "sing-box:"+n.ID || !now.Before(check.ExpiresAt) {
					continue
				}
				if check.State == "available" && check.Verdict == "PASS" {
					p.rank = 0
					break
				}
				if check.CheckedAt.After(p.attempted) {
					p.rank, p.attempted = 2, check.CheckedAt
				}
			}
			if last := a.nodeChecks.serviceAttempts[serviceID+"|"+profile+"|"+n.ID]; p.rank != 0 && last.After(p.attempted) && now.Sub(last) < 10*time.Minute {
				p.rank, p.attempted = 2, last
			}
			priorities[n.ID] = p
		}
	}
	ids := append([]string{}, requested...)
	if len(ids) == 0 {
		for id := range eligible {
			ids = append(ids, id)
		}
		current = strings.TrimPrefix(current, "sing-box:")
		sort.Slice(ids, func(i, j int) bool {
			left, right := priorities[ids[i]], priorities[ids[j]]
			if left.rank != right.rank {
				return left.rank < right.rank
			}
			if left.rank == 0 && (ids[i] == current || ids[j] == current) {
				return ids[i] == current
			}
			if !left.attempted.Equal(right.attempted) {
				return left.attempted.Before(right.attempted)
			}
			return ids[i] < ids[j]
		})
	}
	selected := []string{}
	seen := map[string]bool{}
	for _, id := range ids {
		if eligible[id] && !seen[id] {
			selected = append(selected, id)
			seen[id] = true
		}
		if len(selected) == 3 {
			break
		}
	}
	return selected
}

func (a *App) recordServiceAttempt(serviceID, profile, nodeID string, now time.Time) {
	a.nodeChecks.mu.Lock()
	defer a.nodeChecks.mu.Unlock()
	if a.nodeChecks.serviceAttempts == nil {
		a.nodeChecks.serviceAttempts = map[string]time.Time{}
	}
	// Records without publishable exact evidence also advance the manual
	// search. The private registry already persists valid failed probe history.
	if len(a.nodeChecks.serviceAttempts) >= 2048 {
		oldest := ""
		for key, at := range a.nodeChecks.serviceAttempts {
			if oldest == "" || at.Before(a.nodeChecks.serviceAttempts[oldest]) {
				oldest = key
			}
		}
		delete(a.nodeChecks.serviceAttempts, oldest)
	}
	a.nodeChecks.serviceAttempts[serviceID+"|"+profile+"|"+nodeID] = now
}

func (a *App) checkServiceRoute(ctx context.Context, service catalog.Service, profile string, result *serviceControlResult) {
	if a.TestLab == nil || a.RouteProber == nil {
		return
	}
	route := result.CheckedRoute
	if route == "" {
		route = "direct"
	}
	result.CheckedRoute = route
	probeCtx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	rows := a.TestLab.ProbeRoutesUnrecorded(probeCtx, catalog.Catalog{Services: []catalog.Service{service}}, []string{service.ID}, []string{route}, a.RouteProber)
	if current, err := a.freshNetworkProfile(probeCtx); err != nil || current != profile {
		result.Status, result.Message = "inconclusive", "Сеть изменилась во время проверки."
		return
	}
	if _, err := a.TestLab.RecordRoutesForProfile(profile, rows); err != nil {
		result.Status, result.Message = "inconclusive", "Результат не удалось связать с текущей сетью."
		return
	}
	for _, row := range testlab.AggregateScenarios(rows) {
		result.Status, result.LatencyMS = row.Status, row.LatencyMS
		result.Available = row.Status == "pass" && row.RouteConfirmed && row.RouteProofError == ""
		result.Message = "Изолированная проверка выбранного способа завершена; путь конкретного устройства проверяется отдельно."
		if route == "direct" {
			result.Message = "Проверен прямой доступ с роутера; обход для сервиса не применялся."
		}
		if result.Status != "pass" && result.Status != "fail" && result.Status != "not-ready" || result.Status == "pass" && !result.Available {
			result.Status = "inconclusive"
		}
		break
	}
}
