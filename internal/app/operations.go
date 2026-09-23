package app

import (
	"context"
	"errors"
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
		// memory-only endpoint bypasses admission, never runtime Store reads.
		if r.URL.Path == panelhealth.Path || r.URL.Path == panelSnapshotPath || r.URL.Path == panelInventoryPath || r.URL.Path == panelAuditPath {
			// The general security middleware allows diagnostic reads before
			// account setup. Admission metadata is private even in that state.
			if a.Security == nil || !a.Security.Authenticated(r) {
				w.Header().Set("Cache-Control", "no-store")
				http.Error(w, "administrator login is required", http.StatusUnauthorized)
				return
			}
			if r.URL.Path == panelAuditPath {
				a.panelAudit(w, r)
			} else if r.URL.Path == panelSnapshotPath {
				a.panelSnapshot(w, r)
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
		nodeJobMemoryOnly := r.URL.Path == "/api/v1/node-checks/current" && (r.Method == http.MethodGet || r.Method == http.MethodDelete)
		nodeJobMemoryOnly = nodeJobMemoryOnly || r.URL.Path == "/api/v1/node-autofallback" && (r.Method == http.MethodGet || r.Method == http.MethodDelete)
		nodeJobMemoryOnly = nodeJobMemoryOnly || r.URL.Path == "/api/v1/service-control/current" && (r.Method == http.MethodGet || r.Method == http.MethodDelete)
		nodeJobMemoryOnly = nodeJobMemoryOnly || r.URL.Path == "/api/v1/autonomy" && r.Method == http.MethodGet
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
		if r.Method == http.MethodPut && r.URL.Path == "/api/v1/nfqws2/setup-mode" {
			exclusive = true
		}
		if r.Method == http.MethodPost && r.URL.Path == "/api/v1/dns/service-compare" {
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
		release, err := enter(r.Context())
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
		ctx := context.WithValue(r.Context(), operationContextKey{}, scope)
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
	if errors.Is(err, operationgate.ErrBusy) {
		code = "RESTORE_OPERATION_BUSY"
		message = "Сейчас выполняется другая операция. Дождитесь её завершения и повторите действие. Настройки этим запросом не изменены."
		status = http.StatusConflict
		w.Header().Set("Retry-After", "2")
	}
	recovery := errors.Is(err, operationgate.ErrRecovery)
	if recovery {
		code = "PRIVATE_BACKUP_RECOVERY_REQUIRED"
		message = "После незавершённого восстановления изменения приостановлены. При следующем запуске приложение проверит журнал восстановления. Не удаляйте журнал и не применяйте черновики вручную."
		status = http.StatusServiceUnavailable
	}
	// Identity is cache-independent. Supervisors can recognize a live but busy
	// process without reading locked Stores or inventing dataplane health.
	writeJSON(w, status, map[string]any{"ok": false, "code": code, "error": message, "not_started": true, "live_applied": false, "recovery_required": recovery,
		"name": "RAZVILKA", "version": Version, "process_id": os.Getpid(), "node_recovery": a.nodeRecoverySnapshot()})
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
