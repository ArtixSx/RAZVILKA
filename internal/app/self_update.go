package app

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/ArtixSx/razvilka/internal/updatecheck"
)

func (a *App) selfUpdateCurrent(w http.ResponseWriter, r *http.Request) {
	if a.Security != nil && !a.Security.Authenticated(r) {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "Нужно войти в RAZVILKA."})
		return
	}
	if a.SelfUpdate == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "Обновление приложения недоступно."})
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, a.SelfUpdate.Snapshot())
	case http.MethodDelete:
		job, err := a.SelfUpdate.Cancel()
		if err != nil {
			writeJSON(w, http.StatusConflict, map[string]any{"error": "Подготовка уже завершена. Установку останавливает только сам установщик при ошибке.", "job": job})
			return
		}
		writeJSON(w, http.StatusAccepted, job)
	default:
		methodNotAllowed(w)
	}
}

func (a *App) selfUpdatePrepare(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	if a.SelfUpdate == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "Обновление приложения недоступно."})
		return
	}
	var request struct {
		Confirm string `json:"confirm"`
	}
	if !decodeSelfUpdate(w, r, &request) {
		return
	}
	if request.Confirm != "PREPARE_APP_UPDATE" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "Подтвердите подготовку обновления."})
		return
	}
	cfg := a.Store.Get()
	job, err := a.SelfUpdate.Prepare(cfg.Revision, updatecheck.ConfigFingerprint(cfg))
	if err != nil {
		selfUpdateError(w, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	status := http.StatusAccepted
	if job.State == "blocked" {
		status = http.StatusOK
	}
	writeJSON(w, status, job)
}

func (a *App) selfUpdateApply(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	if a.SelfUpdate == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "Обновление приложения недоступно."})
		return
	}
	var request struct {
		ID       string `json:"job_id"`
		Token    string `json:"review_token"`
		Revision uint64 `json:"config_revision"`
		Confirm  string `json:"confirm"`
	}
	if !decodeSelfUpdate(w, r, &request) {
		return
	}
	if request.Confirm != "INSTALL_APP_UPDATE" || request.ID == "" || request.Token == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "Подтвердите установку подготовленного пакета."})
		return
	}
	release, err := a.privateRestoreAdmission(r.Context())
	if err != nil {
		a.writeOperationFailure(w, err)
		return
	}
	retained := false
	defer func() {
		if !retained {
			release()
		}
	}()
	cfg := a.Store.Get()
	if cfg.Revision != request.Revision {
		selfUpdateError(w, updatecheck.ErrReviewChanged)
		return
	}
	job, err := a.SelfUpdate.Apply(r.Context(), request.ID, request.Token, cfg.Revision, updatecheck.ConfigFingerprint(cfg))
	if err != nil && !errors.Is(err, updatecheck.ErrHandoffUncertain) {
		selfUpdateError(w, err)
		return
	}
	a.SelfUpdate.RetainHandoff(release)
	retained = true
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusAccepted, job)
}

func selfUpdateError(w http.ResponseWriter, err error) {
	code := "SELF_UPDATE_REFUSED"
	message := "Обновление не запущено: проверка не пройдена. Подготовьте пакет заново."
	if errors.Is(err, updatecheck.ErrBusy) {
		code = "SELF_UPDATE_BUSY"
		message = "Другая операция обновления ещё выполняется или требует проверки."
	}
	if errors.Is(err, updatecheck.ErrReviewChanged) {
		code = "SELF_UPDATE_REVIEW_CHANGED"
		message = "Пакет или настройки изменились после просмотра. Подготовьте обновление заново."
	}
	writeJSON(w, http.StatusConflict, map[string]any{"code": code, "error": message, "not_started": true})
}

func (a *App) StartSelfUpdate(ctx context.Context) {
	if a.SelfUpdate != nil {
		a.SelfUpdate.Start(ctx)
		if a.SelfUpdate.StartupPending() {
			release, err := a.Operations.Exclusive(ctx)
			if err != nil {
				a.Operations.Fence()
				return
			}
			// This is startup-owned admission, not an HTTP request's lease.
			// Only the bounded applied-node recovery worker may borrow it. The
			// installer cannot release it until that worker's cleanup has joined.
			job := a.SelfUpdate.Snapshot()
			handoff := &selfUpdateNodeRecovery{app: a, jobID: job.ID, helperPID: job.HelperPID, current: a.SelfUpdate.Snapshot, done: make(chan struct{})}
			a.nodeRecovery.mu.Lock()
			a.nodeRecovery.update = handoff
			a.nodeRecovery.mu.Unlock()
			a.SelfUpdate.RetainHandoff(func() {
				handoff.stopAndWait()
				release()
			})
		}
	}
}

// selfUpdateNodeRecovery is an unexported, process-local capability for one
// startup lease. It cannot be created by a request, restored from JSON or used
// by the ordinary reconciler. A helper in requires-review never grants it.
type selfUpdateNodeRecovery struct {
	mu        sync.Mutex
	app       *App
	jobID     string
	helperPID int
	// Tests replace only the process-status observation, never recovery proof.
	current func() updatecheck.Job
	started bool
	closing bool
	cancel  context.CancelFunc
	done    chan struct{}
}

type selfUpdateNodeRecoveryKey struct{}

func (h *selfUpdateNodeRecovery) guard(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	h.mu.Lock()
	active := h.started && !h.closing
	h.mu.Unlock()
	if !active || h.app.SelfUpdate == nil || !h.app.SelfUpdate.InstallationLocked() {
		return errNodeRecoveryReview
	}
	job := h.current()
	if job.ID != h.jobID || job.State != "restarting" || h.helperPID <= 1 || job.HelperPID != h.helperPID {
		return errNodeRecoveryReview
	}
	return ctx.Err()
}

func (h *selfUpdateNodeRecovery) stopAndWait() {
	h.mu.Lock()
	h.closing = true
	if h.cancel != nil {
		h.cancel()
	}
	if !h.started {
		h.started = true // Prevent a later listener callback from starting work.
		close(h.done)
	}
	h.mu.Unlock()
	<-h.done
}

// StartSelfUpdateNodeRecovery runs only after boot cleanup and the listener are
// ready, before the general scheduler. The listener's existing read-only update
// status exemption lets the installer observe evidence without opening writes.
func (a *App) StartSelfUpdateNodeRecovery(parent context.Context) {
	a.nodeRecovery.mu.Lock()
	handoff := a.nodeRecovery.update
	a.nodeRecovery.mu.Unlock()
	if handoff == nil {
		return
	}
	handoff.mu.Lock()
	if handoff.started || handoff.closing {
		handoff.mu.Unlock()
		return
	}
	ctx, cancel := context.WithTimeout(parent, defaultDataplaneApplyTimeout)
	handoff.started, handoff.cancel = true, cancel
	handoff.mu.Unlock()
	ctx = context.WithValue(ctx, selfUpdateNodeRecoveryKey{}, handoff)
	go func() {
		defer close(handoff.done)
		defer cancel()
		// A dead/replaced helper cancels an in-flight check promptly; the
		// per-phase guard below also fences every transactional write.
		monitored := make(chan struct{})
		go func() {
			defer close(monitored)
			ticker := time.NewTicker(time.Second)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					if handoff.guard(ctx) != nil {
						cancel()
						return
					}
				}
			}
		}()
		defer func() { cancel(); <-monitored }()
		for handoff.guard(ctx) == nil {
			a.nodeRecoveryRound(ctx, time.Now())
			state := a.nodeRecoverySnapshot().State
			if state == "idle" || state == "recovered" || state == "requires-review" {
				return
			}
			timer := time.NewTimer(30 * time.Second)
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
			}
		}
	}()
}

func (a *App) guardSelfUpdateNodeRecovery(ctx context.Context) error {
	if handoff, ok := ctx.Value(selfUpdateNodeRecoveryKey{}).(*selfUpdateNodeRecovery); ok {
		if handoff.app != a {
			return errNodeRecoveryReview
		}
		return handoff.guard(ctx)
	}
	return ctx.Err()
}

func (a *App) nodeRecoveryAdmission(ctx context.Context, exclusive bool) (func(), error) {
	if _, ok := ctx.Value(selfUpdateNodeRecoveryKey{}).(*selfUpdateNodeRecovery); ok {
		if err := a.guardSelfUpdateNodeRecovery(ctx); err != nil {
			return nil, err
		}
		return func() {}, nil // Startup lease remains held through joined cleanup.
	}
	if exclusive {
		return a.Operations.Exclusive(ctx)
	}
	return a.Operations.Enter(ctx)
}
func (a *App) WaitSelfUpdate(ctx context.Context) error {
	if a.SelfUpdate == nil {
		return nil
	}
	return a.SelfUpdate.Wait(ctx)
}

func decodeSelfUpdate(w http.ResponseWriter, r *http.Request, value any) bool {
	d := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
	d.DisallowUnknownFields()
	if d.Decode(value) != nil || d.Decode(&struct{}{}) != io.EOF {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "Некорректный запрос обновления."})
		return false
	}
	return true
}
