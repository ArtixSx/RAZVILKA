package app

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/ArtixSx/razvilka/internal/providerfeed"
)

func (a *App) nodeFeedList(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method == http.MethodPost {
		a.nodeFeedSave(w, r, "")
		return
	}
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	states := []providerfeed.State{}
	if a.NodeFeeds != nil {
		states = a.NodeFeeds.List()
	}
	writeJSON(w, http.StatusOK, map[string]any{"available": a.NodeFeeds != nil, "presets": providerfeed.Builtins(), "sources": states, "max_candidates": providerfeed.MaxCandidates, "max_feeds": providerfeed.MaxFeeds, "persistent": a.NodeFeeds.Persistent(), "scheduled": a.NodeFeeds != nil && a.NodeFeeds.Scheduling()})
}

func decodeFeedRequest(w http.ResponseWriter, r *http.Request, out any) bool {
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 8192))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "Проверьте параметры подписки."})
		return false
	}
	if _, err := strictBackupObject(raw, "preset_id", "url", "format", "limit", "accept_partial", "name", "enabled", "refresh_interval_minutes", "revision", "confirm"); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "Проверьте параметры подписки."})
		return false
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(out) != nil || d.Decode(&struct{}{}) != io.EOF {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "Проверьте параметры подписки."})
		return false
	}
	return true
}

func (a *App) nodeFeedSave(w http.ResponseWriter, r *http.Request, id string) {
	if a.NodeFeeds == nil || !a.NodeFeeds.Persistent() {
		writeFeedError(w, providerfeed.ErrStore)
		return
	}
	var req struct {
		providerfeed.SaveRequest
		Confirm string `json:"confirm"`
	}
	if !decodeFeedRequest(w, r, &req) {
		return
	}
	want := "SAVE_NODE_FEED"
	if id != "" {
		want = "UPDATE_NODE_FEED"
	}
	if req.Confirm != want {
		writeFeedError(w, providerfeed.ErrRequest)
		return
	}
	source, err := a.NodeFeeds.Save(r.Context(), id, req.SaveRequest)
	if err != nil {
		writeFeedError(w, err)
		return
	}
	status := http.StatusCreated
	if id != "" {
		status = http.StatusOK
	}
	writeJSON(w, status, map[string]any{"ok": true, "source": source, "working_routes_changed": false})
}

func (a *App) nodeFeedAction(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if a.NodeFeeds == nil {
		writeFeedError(w, providerfeed.ErrStore)
		return
	}
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/v1/node-feeds/"), "/")
	if len(parts) == 2 && parts[0] == "jobs" {
		var job providerfeed.Job
		var err error
		switch r.Method {
		case http.MethodGet:
			job, err = a.NodeFeeds.Job(parts[1])
		case http.MethodDelete:
			job, err = a.NodeFeeds.CancelJob(parts[1])
		default:
			methodNotAllowed(w)
			return
		}
		if err != nil {
			writeFeedError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "job": job})
		return
	}
	if len(parts) == 2 && parts[1] == "sync" {
		if r.Method != http.MethodPost {
			methodNotAllowed(w)
			return
		}
		var req struct{}
		if !decodeFeedRequest(w, r, &req) {
			return
		}
		job, err := a.NodeFeeds.QueueSync(parts[0])
		if err != nil {
			writeFeedError(w, err)
			return
		}
		writeJSON(w, http.StatusAccepted, map[string]any{"ok": true, "job": job, "working_routes_changed": false})
		return
	}
	if len(parts) != 1 || parts[0] == "" {
		http.NotFound(w, r)
		return
	}
	switch r.Method {
	case http.MethodPut:
		a.nodeFeedSave(w, r, parts[0])
	case http.MethodGet:
		source, err := a.NodeFeeds.Saved(parts[0])
		if err != nil {
			writeFeedError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "source": source})
	case http.MethodDelete:
		var req struct {
			Revision uint64 `json:"revision"`
			Confirm  string `json:"confirm"`
		}
		if !decodeFeedRequest(w, r, &req) {
			return
		}
		if req.Confirm != "DELETE_NODE_FEED" {
			writeFeedError(w, providerfeed.ErrRequest)
			return
		}
		if err := a.NodeFeeds.Delete(r.Context(), parts[0], req.Revision); err != nil {
			writeFeedError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "working_routes_changed": false, "nodes_retained": true})
	default:
		methodNotAllowed(w)
	}
}

func writeFeedError(w http.ResponseWriter, err error) {
	status, message := http.StatusServiceUnavailable, "Хранилище подписок временно недоступно."
	switch {
	case errors.Is(err, providerfeed.ErrRequest):
		status, message = http.StatusBadRequest, "Проверьте название, публичную HTTPS-ссылку и интервал обновления от 15 минут до 7 дней. Для другого адреса добавьте новую подписку."
	case errors.Is(err, providerfeed.ErrConflict):
		status, message = http.StatusConflict, "Подписка изменилась. Обновите список и повторите действие."
	case errors.Is(err, providerfeed.ErrNotFound):
		status, message = http.StatusNotFound, "Подписка или задача не найдена."
	case errors.Is(err, providerfeed.ErrBusy):
		status, message = http.StatusConflict, "Очередь обновлений заполнена. Дождитесь завершения текущей задачи."
	case errors.Is(err, providerfeed.ErrSize):
		status, message = http.StatusBadRequest, "Достигнут лимит подписок или размер сохранённых данных."
	case errors.Is(err, providerfeed.ErrCapacity):
		status, message = http.StatusConflict, "Локальный каталог заполнен (512 узлов). Удалите неиспользуемые узлы и повторите обновление. Сохранённые подключения не удалялись."
	}
	writeJSON(w, status, map[string]any{"ok": false, "code": providerfeed.ErrorCode(err), "error": message, "working_routes_changed": false})
}

func (a *App) nodeFeedSync(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	if a.NodeFeeds == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"ok": false, "error": "Синхронизация источников сейчас недоступна."})
		return
	}
	var request struct {
		providerfeed.Request
		Confirm string `json:"confirm"`
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&request) != nil || decoder.Decode(&struct{}{}) != io.EOF || request.Confirm != "SYNC_NODE_FEED" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "Выберите источник и подтвердите получение кандидатов."})
		return
	}
	result, err := a.NodeFeeds.Sync(r.Context(), request.Request)
	if err != nil {
		status, message := http.StatusBadGateway, "Не удалось получить кандидатов. Сохранённые узлы и рабочие маршруты не изменены."
		switch {
		case errors.Is(err, providerfeed.ErrRequest):
			status, message = http.StatusBadRequest, "Нужен известный источник либо корректная публичная HTTPS-подписка."
		case errors.Is(err, providerfeed.ErrPartial):
			status, message = http.StatusConflict, "Часть записей отклонена. Подтвердите импорт только принятых кандидатов."
		case errors.Is(err, providerfeed.ErrBusy):
			status, message = http.StatusConflict, "Получение кандидатов уже выполняется."
		case errors.Is(err, providerfeed.ErrSize):
			status, message = http.StatusBadRequest, "Источник превышает допустимый размер или число записей."
		case errors.Is(err, providerfeed.ErrFormat):
			status, message = http.StatusBadRequest, "Источник не содержит поддерживаемой выборки узлов."
		case errors.Is(err, providerfeed.ErrStore):
			status, message = http.StatusServiceUnavailable, "Запись кандидатов не подтверждена. Проверьте состояние приватного хранилища."
		case errors.Is(err, providerfeed.ErrCapacity):
			status, message = http.StatusConflict, "Локальный каталог заполнен (512 узлов). Удалите неиспользуемые узлы и повторите обновление. Сохранённые подключения не удалялись."
		}
		writeJSON(w, status, map[string]any{"ok": false, "code": providerfeed.ErrorCode(err), "error": message, "result": result, "working_routes_changed": false})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "result": result, "working_routes_changed": false, "note": "Кандидаты требуют отдельной точной проверки сервиса в текущей сети. Получение источника не продлевает результат проверки."})
}
