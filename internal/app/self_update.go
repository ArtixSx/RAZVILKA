package app

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"

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
			a.SelfUpdate.RetainHandoff(release)
		}
	}
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
