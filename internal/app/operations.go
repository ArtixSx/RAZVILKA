package app

import (
	"context"
	"errors"
	"fmt"
	"github.com/ArtixSx/razvilka/internal/dataplane"
	"net/http"
	"os"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/ArtixSx/razvilka/internal/operationgate"
	"github.com/ArtixSx/razvilka/internal/panelhealth"
)

type operationContextKey struct{}
type operationScope struct {
	app       *App
	exclusive bool
	mu        sync.Mutex
	active    bool
	restoring bool
	release   func()
}

func (s *operationScope) closeRequest() {
	s.mu.Lock()
	s.active = false
	release := !s.restoring
	s.mu.Unlock()
	if release {
		s.release()
	}
}

func (s *operationScope) restoreAdmission() (func(), error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.exclusive || !s.active || s.restoring {
		return nil, operationgate.ErrBusy
	}
	s.restoring = true
	var once sync.Once
	return func() {
		once.Do(func() {
			s.mu.Lock()
			s.restoring = false
			release := !s.active
			s.mu.Unlock()
			if release {
				s.release()
			}
		})
	}, nil
}

// Internal runtime callers retain the same concrete admission through their
// Store publication and joined cleanup. A private runtime can borrow it once;
// unknown cleanup keeps the original owner after the outer caller returns.
func (a *App) scopedRuntimeOperation(ctx context.Context) (context.Context, func(), error) {
	if a == nil || ctx == nil {
		return nil, nil, operationgate.ErrBusy
	}
	bounded, cancel := context.WithTimeout(ctx, defaultDataplaneApplyTimeout)
	admitted, release, err := a.Operations.ExclusiveContext(bounded)
	if err != nil {
		cancel()
		return nil, nil, err
	}
	scope := &operationScope{app: a, exclusive: true, active: true, release: func() { release(); cancel() }}
	return context.WithValue(admitted, operationContextKey{}, scope), scope.closeRequest, nil
}

// Protect reads too: GET /devices performs discovery and persists metadata.
// Current request-owned probe goroutines are joined before handlers return.
// Any future detached task MUST retain its own admission until all writes and
// cleanup finish; inheriting the context value does not extend ownership.
func (a *App) operationMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/components/recovery" || r.URL.Path == "/api/v1/self-update/recovery" {
			// Recovery owns exact inspection/repair admission behind auth and CSRF.
			next.ServeHTTP(w, r)
			return
		}
		if a.strategyCompatibilityPending() && strings.HasPrefix(r.URL.Path, "/api/") && !strings.HasPrefix(r.URL.Path, "/api/v1/auth/") {
			if a.Security == nil || !a.Security.Authenticated(r) {
				http.Error(w, "administrator login is required", http.StatusUnauthorized)
				return
			}
			if r.URL.Path == "/api/v1/strategy-lab" && r.Method == http.MethodGet {
				a.strategyLabSnapshot(w, r)
				return
			}
			if r.URL.Path != panelhealth.Path && r.URL.Path != panelSnapshotPath && r.URL.Path != panelDeviceBrowsePath && r.URL.Path != panelCommunityBrowsePath && r.URL.Path != panelNodeBrowsePath && r.URL.Path != panelInventoryPath && r.URL.Path != panelAutonomyPath && r.URL.Path != panelAuditPath && r.URL.Path != panelDoctorPath && r.URL.Path != "/api/v1/metrics" && r.URL.Path != "/api/v1/connections" {
				writeStrategyCompatibilityRecovery(w, true)
				return
			}
		}
		// Security.Middleware remains outside this middleware. Only this
		// memory-only endpoints bypass admission, never runtime Store reads.
		if r.URL.Path == panelhealth.Path || r.URL.Path == panelSnapshotPath || r.URL.Path == panelDeviceBrowsePath || r.URL.Path == panelCommunityBrowsePath || r.URL.Path == panelNodeBrowsePath || r.URL.Path == panelInventoryPath || r.URL.Path == panelAutonomyPath || r.URL.Path == panelAuditPath || r.URL.Path == panelDoctorPath || r.URL.Path == "/api/v1/metrics" || r.URL.Path == "/api/v1/connections" {
			// The general security middleware allows diagnostic reads before
			// account setup. Admission metadata is private even in that state.
			if a.Security == nil || !a.Security.Authenticated(r) {
				w.Header().Set("Cache-Control", "no-store")
				http.Error(w, "administrator login is required", http.StatusUnauthorized)
				return
			}
			if r.URL.Path == "/api/v1/metrics" {
				a.metrics(w, r)
			} else if r.URL.Path == "/api/v1/connections" {
				a.connections(w, r)
			} else if r.URL.Path == panelAuditPath {
				a.panelAudit(w, r)
			} else if r.URL.Path == panelDoctorPath {
				a.panelDoctor(w, r)
			} else if r.URL.Path == panelSnapshotPath {
				a.panelSnapshot(w, r)
			} else if r.URL.Path == panelDeviceBrowsePath {
				a.panelDeviceBrowse(w, r)
			} else if r.URL.Path == panelNodeBrowsePath {
				a.panelNodeBrowse(w, r)
			} else if r.URL.Path == panelCommunityBrowsePath {
				a.panelCommunityBrowse(w, r)
			} else if r.URL.Path == panelAutonomyPath {
				a.panelAutonomy(w, r)
			} else if r.URL.Path == panelInventoryPath {
				a.panelInventory(w, r)
			} else {
				panelhealth.Handler(&a.Operations).ServeHTTP(w, r)
			}
			return
		}
		updateLocked := a.SelfUpdate != nil && a.SelfUpdate.InstallationLocked()
		updatePending := updateLocked || a.PendingSelfUpdateRecovery()
		if updatePending && strings.HasPrefix(r.URL.Path, "/api/v1/auth/") && r.URL.Path != "/api/v1/auth/status" && r.URL.Path != "/api/v1/auth/login" && r.URL.Path != "/api/v1/auth/logout" {
			a.writeOperationFailure(w, operationgate.ErrBusy)
			return
		}
		if updateLocked && r.URL.Path == "/api/v1/status" && r.Method == http.MethodGet {
			next.ServeHTTP(w, r)
			return
		}
		a.interruptAutomation(r)
		nodeJobOwnsAdmission := (r.URL.Path == "/api/v1/node-checks" || r.URL.Path == "/api/v1/service-control/jobs" || r.URL.Path == "/api/v1/service-control/runtime") && r.Method == http.MethodPost
		nodeJobOwnsAdmission = nodeJobOwnsAdmission || r.URL.Path == "/api/v1/dns/service-compare" && r.Method == http.MethodPost
		nodeJobOwnsAdmission = nodeJobOwnsAdmission || isNodeApplyPath(r)
		nodeJobOwnsAdmission = nodeJobOwnsAdmission || isScopedDNSApplyPath(r)
		// This caller delegates admission to the original retained runtime.
		// A pending Stop must join its existing owner even while it fences new
		// operations; request middleware must not create a second admission.
		nodeJobOwnsAdmission = nodeJobOwnsAdmission || r.URL.Path == managedNFQListRuntimePath && r.Method == http.MethodPost
		nodeJobMemoryOnly := r.URL.Path == "/api/v1/node-checks/current" && (r.Method == http.MethodGet || r.Method == http.MethodDelete)
		nodeJobMemoryOnly = nodeJobMemoryOnly || r.URL.Path == "/api/v1/node-autofallback" && (r.Method == http.MethodGet || r.Method == http.MethodDelete)
		nodeJobMemoryOnly = nodeJobMemoryOnly || r.URL.Path == "/api/v1/service-control/current" && (r.Method == http.MethodGet || r.Method == http.MethodDelete)
		nodeJobMemoryOnly = nodeJobMemoryOnly || r.URL.Path == "/api/v1/self-update/current" && (r.Method == http.MethodGet || r.Method == http.MethodDelete)
		communityOwnsAdmission := r.URL.Path == "/api/v1/community/source-preview" && r.Method == http.MethodPost || strings.HasPrefix(r.URL.Path, "/api/v1/community/services/") && (r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/preview") || r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/import"))
		if !strings.HasPrefix(r.URL.Path, "/api/") || strings.HasPrefix(r.URL.Path, "/api/v1/auth/") || r.URL.Path == "/api/v1/connections/stream" && r.Method == http.MethodGet || nodeJobOwnsAdmission || nodeJobMemoryOnly || communityOwnsAdmission {
			// Auth changes only credentials (not restored); SSE reads only telemetry.
			// Holding a shared admission for an endless stream would starve restore.
			// Detached node jobs acquire their own gate before reading stores; their
			// status/cancel handlers access only memory and remain usable meanwhile.
			next.ServeHTTP(w, r)
			return
		}
		exclusive := (r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/api/v1/nodes/")) || strings.HasPrefix(r.URL.Path, "/api/v1/autonomy/services/") && r.Method == http.MethodDelete || r.URL.Path == "/api/v1/autonomy" && r.Method == http.MethodPut || r.URL.Path == "/api/v1/autonomy/services" && r.Method == http.MethodPost || r.Method == http.MethodPost && (r.URL.Path == "/api/v1/nodes/delete-batch" || r.URL.Path == "/api/v1/apply" || r.URL.Path == "/api/v1/self-update/apply" || r.URL.Path == "/api/v1/service-control/runtime" || r.URL.Path == "/api/v1/private-backups/import" || r.URL.Path == "/api/v1/diagnostics/usque/repair" || strings.HasPrefix(r.URL.Path, "/api/v1/nodes/") && strings.HasSuffix(r.URL.Path, "/apply"))
		if r.Method == http.MethodPost && (r.URL.Path == networkPolicyReviewPath || r.URL.Path == resourceExclusionsPath) {
			exclusive = true
		}
		if r.Method == http.MethodGet && r.URL.Path == "/api/v1/plan" {
			// Managed list review reads its original control/source under the
			// same exclusive admission; it cannot upgrade a shared request.
			exclusive = true
		}
		if r.Method == http.MethodGet && r.URL.Path == managedNFQBundlePlanPath {
			// This bounded read compares the actual retained control owner.
			exclusive = true
		}
		if r.Method == http.MethodGet && (r.URL.Path == "/api/v1/plan" || r.URL.Path == "/api/v1/status" || r.URL.Path == "/api/v1/service-control" || r.URL.Path == "/api/v1/components") || r.Method == http.MethodPut && r.URL.Path == "/api/v1/service-control" {
			// Bounded managed readers retain the original request admission.
			// Their concrete runtime check cannot upgrade a shared operation.
			exclusive = true
		}
		if r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/api/v1/strategy-lab/candidates/") && strings.HasSuffix(strings.TrimRight(r.URL.Path, "/"), "/validate") {
			// Supervised compatibility uses the original request operation for
			// its exact source publication; a shared request cannot upgrade it.
			exclusive = true
		}
		if r.Method == http.MethodPost && r.URL.Path == "/api/v1/strategy-lab/selections" {
			exclusive = true
		}
		if r.Method == http.MethodPut && (r.URL.Path == "/api/v1/nfqws2/setup-mode" || r.URL.Path == "/api/v1/nfqws2/discord-repair") {
			exclusive = true
		}
		if r.Method == http.MethodPut && strings.HasPrefix(r.URL.Path, "/api/v1/services/") {
			// Serialize a reviewed profile lookup and service CAS with profile CRUD.
			exclusive = true
		}
		if r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/api/v1/custom-services/") {
			// The route guard and catalog/config deletion form one review. A
			// concurrent shared profile import must not enable a newer draft
			// between that guard and deletion of the service's Store entries.
			exclusive = true
		}
		// Subscription removal also withdraws autonomy permission. Serialize it
		// with policy saves, automatic re-creation, imports and manual Apply.
		if r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/api/v1/node-feeds/") && !strings.Contains(strings.TrimPrefix(r.URL.Path, "/api/v1/node-feeds/"), "/") {
			exclusive = true
		}
		if r.Method != http.MethodGet && (strings.HasPrefix(r.URL.Path, "/api/v1/amneziawg") || strings.HasPrefix(r.URL.Path, "/api/v1/warp/")) {
			exclusive = true
		}
		if (r.URL.Path == wireGuardProfilesPath || strings.HasPrefix(r.URL.Path, wireGuardProfilesPath+"/")) && (r.Method == http.MethodPost || r.Method == http.MethodPut || r.Method == http.MethodDelete) {
			exclusive = true
		}
		if r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/api/v1/components/") {
			// Package mutation cannot overlap network Apply or background repair.
			exclusive = true
		}
		if r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/api/v1/community/services/") && strings.HasSuffix(r.URL.Path, "/import") {
			exclusive = true
		}
		labeled := operationgate.WithLabel(r.Context(), requestOperationLabel(r))
		admitted := labeled
		enter := func(ctx context.Context) (func(), error) {
			if !exclusive {
				return a.Operations.Enter(ctx)
			}
			owned, release, err := a.Operations.ExclusiveContext(ctx)
			if err == nil {
				admitted = owned
			}
			return release, err
		}
		release, err := enter(labeled)
		if errors.Is(err, operationgate.ErrBusy) {
			statusRead := r.Method == http.MethodGet && r.URL.Path == "/api/v1/status"
			release, err = waitForAdmission(labeled, enter, a.admissionPatience(r), statusRead)
		}
		if err != nil {
			a.writeOperationFailure(w, err)
			return
		}
		scope := &operationScope{app: a, exclusive: exclusive, active: true, release: release}
		defer func() {
			scope.closeRequest()
			if r.Method != http.MethodGet && r.Method != http.MethodHead {
				a.wakePanelSnapshot()
			}
		}()
		ctx := context.WithValue(admitted, operationContextKey{}, scope)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// Internal callers must enter as well. A request already admitted exclusively
// reuses its admission instead of trying to acquire the gate twice.
func (a *App) privateRestoreAdmission(ctx context.Context) (func(), error) {
	if scope, ok := ctx.Value(operationContextKey{}).(*operationScope); ok && scope.app == a {
		return scope.restoreAdmission()
	}
	return a.Operations.Exclusive(ctx)
}

// privateExclusiveOperation borrows an actual request-owned exclusive
// capability, or issues one at admission for an internal operation. A shared
// request cannot upgrade and a copied expired request scope cannot revive it.
// Borrowing retains the outer request admission through owner cleanup; the
// returned release must be called after all work joins.
func (a *App) privateExclusiveOperation(ctx context.Context) (context.Context, func(), error) {
	if a == nil || ctx == nil {
		return nil, nil, operationgate.ErrBusy
	}
	if scope, ok := ctx.Value(operationContextKey{}).(*operationScope); ok && scope.app == a {
		if err := a.Operations.WithExclusiveContext(ctx, func() error { return nil }); err != nil {
			return nil, nil, err
		}
		release, err := scope.restoreAdmission()
		if err != nil {
			return nil, nil, err
		}
		return ctx, release, nil
	}
	return a.Operations.ExclusiveContext(ctx)
}

func writeOperationFailure(w http.ResponseWriter, err error) {
	(&App{}).writeOperationFailure(w, err)
}

func (a *App) writeOperationFailure(w http.ResponseWriter, err error) {
	w.Header().Set("Cache-Control", "no-store")
	code := "OPERATION_CANCELED"
	message := "Действие отменено до начала. Настройки не изменены."
	status := http.StatusRequestTimeout
	var holder map[string]any
	if errors.Is(err, operationgate.ErrBusy) {
		code = "RESTORE_OPERATION_BUSY"
		message = "Сейчас выполняется другая операция. Дождитесь её завершения и повторите действие. Настройки этим запросом не изменены."
		status = http.StatusConflict
		w.Header().Set("Retry-After", "2")
		if label, since, ok := a.Operations.Holder(); ok && label != "" {
			elapsed := int64(time.Since(since) / time.Second)
			message = fmt.Sprintf("Сейчас выполняется: %s (%s). Дождитесь её завершения и повторите действие. Настройки этим запросом не изменены.", label, operationAge(elapsed))
			holder = map[string]any{"label": label, "seconds": elapsed}
		}
	}
	recovery := errors.Is(err, operationgate.ErrRecovery)
	if errors.Is(err, errComponentRecovery) {
		code, status = "COMPONENT_RECOVERY_REQUIRED", http.StatusServiceUnavailable
		message = "Обновление компонента ещё не подтверждено рабочим процессом. Прежняя версия сохранена. Откройте журнал обновления; повторная установка автоматически не запускается."
	}
	if errors.Is(err, errSelfUpdateRecovery) {
		code, status = "SELF_UPDATE_RECOVERY_REQUIRED", http.StatusServiceUnavailable
		message = "Обновление приложения требует проверки сохранённой транзакции. Автоматические изменения приостановлены; повтор установщика не запускается."
	}
	if recovery {
		code = "PRIVATE_BACKUP_RECOVERY_REQUIRED"
		message = "После незавершённого восстановления изменения приостановлены. При следующем запуске приложение проверит журнал восстановления. Не удаляйте журнал и не применяйте черновики вручную."
		status = http.StatusServiceUnavailable
		if errors.Is(err, operationgate.ErrJournalRecovery) {
			// A restart does not settle this fence; supervisors keep the process.
			code = "DATAPLANE_RECOVERY_REQUIRED"
			message = "Предыдущая сетевая транзакция завершилась без подтверждённого отката. Изменения приостановлены до проверки журнала маршрутов; перезапуск этого не исправит. Не удаляйте журнал вручную."
		}
	}
	if errors.Is(err, errDataplaneBootRecovery) {
		code, status = "DATAPLANE_RECOVERY_REQUIRED", http.StatusServiceUnavailable
		message = "Восстановление маршрутов после запуска не подтверждено. Автоматические изменения приостановлены до проверки журнала; защитный запрет сохранён."
	}
	// Identity is cache-independent. Supervisors can recognize a live but busy
	// process without reading locked Stores or inventing dataplane health.
	body := map[string]any{"ok": false, "code": code, "error": message, "not_started": true, "live_applied": false, "recovery_required": recovery,
		"name": "RAZVILKA", "version": Version, "process_id": os.Getpid(), "node_recovery": a.nodeRecoverySnapshot()}
	if errors.Is(err, errComponentRecovery) || errors.Is(err, errSelfUpdateRecovery) {
		body["recovery_required"] = true
	}
	if holder != nil {
		body["operation"] = holder
	}
	writeJSON(w, status, body)
}

func operationAge(seconds int64) string {
	if seconds < 60 {
		return fmt.Sprintf("идёт %d с", max(seconds, 1))
	}
	return fmt.Sprintf("идёт %d мин", seconds/60)
}

// operatorIntent reports a request the operator started with a click. Beyond
// mutations, the plan previews behind "Установить"/"Применить" are GET but
// still express intent; periodic panel reads are not.
func operatorIntent(r *http.Request) bool {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		return true
	}
	// The panel reads the plan passively on every page load. Treating that as
	// intent cancelled a running autopilot transaction mid-activation, whose
	// rollback then failed and fenced the router. Only the plan read behind a
	// click interrupts automation.
	if r.Header.Get("X-Razvilka-Read") == "passive" {
		return false
	}
	return r.URL.Path == "/api/v1/plan" || strings.HasPrefix(r.URL.Path, "/api/v1/components/") && strings.HasSuffix(r.URL.Path, "/plan")
}

// admissionPatience bounds how long a panel request waits for a busy gate.
// Reads only ride over short observations; an operator action interrupts
// automation and waits for its cleanup. Status only rides over a short read
// or publication; supervisors still see a prolonged busy owner promptly.
func (a *App) admissionPatience(r *http.Request) time.Duration {
	if a.AdmissionPatience <= 0 {
		return 0
	}
	if r.URL.Path == "/api/v1/status" {
		if r.Method != http.MethodGet {
			return 0
		}
		return min(a.AdmissionPatience, 125*time.Millisecond)
	}
	if operatorIntent(r) {
		return a.AdmissionPatience
	}
	return min(a.AdmissionPatience, 2*time.Second)
}

// waitForAdmission retries a busy admission until patience runs out. The gate
// itself never queues; this only spares the operator an immediate refusal.
func waitForAdmission(ctx context.Context, enter func(context.Context) (func(), error), patience time.Duration, statusRead bool) (func(), error) {
	if patience <= 0 {
		return nil, operationgate.ErrBusy
	}
	cutoff := time.Now().Add(patience)
	deadline := time.NewTimer(patience)
	defer deadline.Stop()
	interval := 100 * time.Millisecond
	if statusRead {
		interval = 10 * time.Millisecond
	}
	retry := time.NewTicker(interval)
	defer retry.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-deadline.C:
			if statusRead && ctx.Err() != nil {
				return nil, ctx.Err()
			}
			return nil, operationgate.ErrBusy
		case <-retry.C:
			if statusRead {
				if err := ctx.Err(); err != nil {
					return nil, err
				}
				if !time.Now().Before(cutoff) {
					return nil, operationgate.ErrBusy
				}
			}
			if release, err := enter(ctx); !errors.Is(err, operationgate.ErrBusy) {
				if statusRead && err == nil {
					// Admission keeps the original request context. A slow guard
					// can grant after cancellation or the grace cutoff; release
					// that owner before refusing, without ever running the handler.
					if err := ctx.Err(); err != nil {
						release()
						return nil, err
					}
					if !time.Now().Before(cutoff) {
						release()
						return nil, operationgate.ErrBusy
					}
				}
				return release, err
			}
		}
	}
}

// requestOperationLabel names a panel request for the busy explanation, by
// section only: never IDs, addresses or other request data.
func requestOperationLabel(r *http.Request) string {
	path := r.URL.Path
	switch {
	case strings.HasPrefix(path, "/api/v1/components/"):
		return "установка или обновление компонента"
	case path == "/api/v1/apply" || path == "/api/v1/plan":
		return "проверка и применение изменений"
	case strings.HasPrefix(path, "/api/v1/node-checks"):
		return "проверка подключений"
	case strings.HasPrefix(path, "/api/v1/nodes") || strings.HasPrefix(path, "/api/v1/node-"):
		return "изменение подключений"
	case strings.HasPrefix(path, "/api/v1/service-control"):
		return "управление сервисами"
	case strings.HasPrefix(path, "/api/v1/dns"):
		return "настройка DNS"
	case strings.HasPrefix(path, "/api/v1/autonomy"):
		return "настройки автопилота"
	case strings.HasPrefix(path, "/api/v1/private-backups"):
		return "восстановление резервной копии"
	case strings.HasPrefix(path, "/api/v1/self-update"):
		return "обновление RAZVILKA"
	case strings.HasPrefix(path, "/api/v1/warp") || strings.HasPrefix(path, "/api/v1/amneziawg") || strings.HasPrefix(path, "/api/v1/cloudflare"):
		return "настройка туннеля"
	case strings.HasPrefix(path, "/api/v1/sources") || strings.HasPrefix(path, "/api/v1/community"):
		return "обновление списков"
	}
	if r.Method == http.MethodGet || r.Method == http.MethodHead {
		return "чтение данных панели"
	}
	return "действие в панели"
}

// jobOperationLabel names queued jobs and scheduled tasks for the same
// explanation, again with fixed words only.
func jobOperationLabel(kind string) string {
	switch kind {
	case "check", "service-checks":
		return "проверка сервисов"
	case "select":
		return "подбор подключения для сервиса"
	case "node-check":
		return "проверка подключений"
	case "node-apply":
		return "применение подключения"
	case "dns-apply":
		return "применение DNS"
	case "dns-compare":
		return "сравнение DNS"
	case "stop":
		return "остановка обходов"
	case "resume":
		return "запуск обходов"
	case "node-recovery":
		return "восстановление подключений"
	case "node-fallback":
		return "поиск резервного подключения"
	case "legacy-routes":
		return "обновление адресов маршрутов"
	case "feeds":
		return "автопилот: проверка сервисов и подписок"
	}
	return "фоновая операция"
}

func (a *App) backgroundRound(ctx context.Context, round int) {
	release, err := a.Operations.Exclusive(ctx)
	if err != nil {
		return // A restore takes precedence; retry at the next scheduled round.
	}
	defer release()
	if a.Store == nil {
		return
	}
	base := a.Store.Get()
	if base.SafeMode || base.ServiceControl.Stopped {
		return
	}
	// A saved plan is not authority to bypass a later Safe Mode/stop/revision.
	guard := func(c context.Context) error {
		if c.Err() != nil {
			return c.Err()
		}
		current := a.Store.Get()
		if current.SafeMode || current.ServiceControl.Stopped || !reflect.DeepEqual(current, base) {
			return dataplane.ErrReviewChanged
		}
		return nil
	}
	if a.Dataplane != nil {
		refreshCtx, refreshCancel := context.WithTimeout(ctx, 90*time.Second)
		_, _ = a.Dataplane.RefreshCommitted(dataplane.WithReviewGuard(refreshCtx, guard))
		refreshCancel()
	}
	a.backgroundWarpHealth(ctx)
	if round%2 == 1 {
		if a.backgroundSmartRoute(ctx) {
			a.backgroundAutopilotApply(ctx)
		}
	}
}
