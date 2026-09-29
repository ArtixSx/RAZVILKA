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
	defer s.mu.Unlock()
	s.active = false
	if !s.restoring {
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
			defer s.mu.Unlock()
			s.restoring = false
			if !s.active {
				s.release()
			}
		})
	}, nil
}

// Protect reads too: GET /devices performs discovery and persists metadata.
// Current request-owned probe goroutines are joined before handlers return.
// Any future detached task MUST retain its own admission until all writes and
// cleanup finish; inheriting the context value does not extend ownership.
func (a *App) operationMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Security.Middleware remains outside this middleware. Only this
		// memory-only endpoints bypass admission, never runtime Store reads.
		if r.URL.Path == panelhealth.Path || r.URL.Path == panelSnapshotPath || r.URL.Path == panelInventoryPath || r.URL.Path == panelAutonomyPath || r.URL.Path == panelAuditPath || r.URL.Path == "/api/v1/metrics" || r.URL.Path == "/api/v1/connections" {
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
			} else if r.URL.Path == panelSnapshotPath {
				a.panelSnapshot(w, r)
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
		if updateLocked && strings.HasPrefix(r.URL.Path, "/api/v1/auth/") && r.URL.Path != "/api/v1/auth/status" && r.URL.Path != "/api/v1/auth/login" && r.URL.Path != "/api/v1/auth/logout" {
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
		if r.Method == http.MethodPut && (r.URL.Path == "/api/v1/nfqws2/setup-mode" || r.URL.Path == "/api/v1/nfqws2/discord-repair") {
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
		enter := a.Operations.Enter
		if r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/api/v1/community/services/") && strings.HasSuffix(r.URL.Path, "/import") {
			exclusive = true
		}
		if exclusive {
			enter = a.Operations.Exclusive
		}
		labeled := operationgate.WithLabel(r.Context(), requestOperationLabel(r))
		release, err := enter(labeled)
		if errors.Is(err, operationgate.ErrBusy) {
			release, err = waitForAdmission(labeled, enter, a.admissionPatience(r))
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
		ctx := context.WithValue(labeled, operationContextKey{}, scope)
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
	// Identity is cache-independent. Supervisors can recognize a live but busy
	// process without reading locked Stores or inventing dataplane health.
	body := map[string]any{"ok": false, "code": code, "error": message, "not_started": true, "live_applied": false, "recovery_required": recovery,
		"name": "RAZVILKA", "version": Version, "process_id": os.Getpid(), "node_recovery": a.nodeRecoverySnapshot()}
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
	return r.URL.Path == "/api/v1/plan" || strings.HasPrefix(r.URL.Path, "/api/v1/components/") && strings.HasSuffix(r.URL.Path, "/plan")
}

// admissionPatience bounds how long a panel request waits for a busy gate.
// Reads only ride over short observations; an operator action interrupts
// automation and waits for its cleanup. The status endpoint never waits:
// supervisors must see RESTORE_OPERATION_BUSY promptly.
func (a *App) admissionPatience(r *http.Request) time.Duration {
	if a.AdmissionPatience <= 0 || r.URL.Path == "/api/v1/status" {
		return 0
	}
	if operatorIntent(r) {
		return a.AdmissionPatience
	}
	return min(a.AdmissionPatience, 2*time.Second)
}

// waitForAdmission retries a busy admission until patience runs out. The gate
// itself never queues; this only spares the operator an immediate refusal.
func waitForAdmission(ctx context.Context, enter func(context.Context) (func(), error), patience time.Duration) (func(), error) {
	if patience <= 0 {
		return nil, operationgate.ErrBusy
	}
	deadline := time.NewTimer(patience)
	defer deadline.Stop()
	retry := time.NewTicker(100 * time.Millisecond)
	defer retry.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-deadline.C:
			return nil, operationgate.ErrBusy
		case <-retry.C:
			if release, err := enter(ctx); !errors.Is(err, operationgate.ErrBusy) {
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
