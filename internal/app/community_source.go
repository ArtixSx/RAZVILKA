package app

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/ArtixSx/razvilka/internal/community"
)

func writeCommunityFailure(w http.ResponseWriter, err error) {
	status, code, message := http.StatusBadGateway, "SERVICE_SOURCE_UNAVAILABLE", "Не удалось получить список источника. Рабочие сервисы не изменены. Повторите запрос или используйте локальный файл/текст."
	switch {
	case errors.Is(err, community.ErrCustomSource):
		status, code, message = 400, "SERVICE_SOURCE_INVALID", "Укажите HTTPS-ссылку на файл GitHub или поддержанный список доменов/CIDR, а не страницу репозитория либо VLESS-подписку."
	case errors.Is(err, community.ErrPreviewExpired):
		status, code, message = 409, "SERVICE_PREVIEW_EXPIRED", "Предпросмотр истёк. Повторите разбор исходного файла или текста."
	case errors.Is(err, context.DeadlineExceeded):
		status, code, message = 504, "SERVICE_SOURCE_TIMEOUT", "Источник не ответил вовремя. Предпросмотр не завершён; попробуйте файл или текст."
	case errors.Is(err, context.Canceled):
		status, code, message = 408, "SERVICE_SOURCE_CANCELED", "Загрузка отменена. Сервис не импортирован."
	}
	var sourceErr *community.SourceError
	part := ""
	if errors.As(err, &sourceErr) {
		part = sourceErr.Part
		if part == "cidrs" {
			message = "Не удалось загрузить сети IP/CIDR. " + message
		} else if part == "domains" {
			message = "Не удалось загрузить домены. " + message
		}
	}
	writeJSON(w, status, map[string]any{"code": code, "error": message, "source_part": part, "not_started": true, "live_applied": false})
}
func (a *App) communitySourcePreview(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	if a.Security == nil || !a.Security.Authenticated(r) {
		writeJSON(w, 401, map[string]any{"error": "Требуется авторизация."})
		return
	}
	if a.Community == nil || a.Store == nil {
		writeJSON(w, 503, map[string]any{"error": "Каталог недоступен."})
		return
	}
	var in struct {
		community.CustomSource
		ExpectedRevision *uint64 `json:"expected_revision"`
		Confirm          string  `json:"confirm"`
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 300<<10))
	dec.DisallowUnknownFields()
	if dec.Decode(&in) != nil || dec.Decode(&struct{}{}) != io.EOF || in.Confirm != "PREVIEW_SERVICE_SOURCE" || in.ExpectedRevision == nil {
		writeCommunityFailure(w, community.ErrCustomSource)
		return
	}
	if a.Store.Get().Revision != *in.ExpectedRevision {
		writeJSON(w, 409, map[string]any{"error": "Настройки изменились. Обновите страницу."})
		return
	}
	preview, err := a.Community.PreviewCustom(r.Context(), in.CustomSource, a.catalogSnapshot().Services)
	if err != nil {
		writeCommunityFailure(w, err)
		return
	}
	if !a.Security.Authenticated(r) {
		writeJSON(w, 401, map[string]any{"error": "Сеанс завершён."})
		return
	}
	if a.Store.Get().Revision != *in.ExpectedRevision {
		writeJSON(w, 409, map[string]any{"error": "Настройки изменились во время разбора."})
		return
	}
	writeJSON(w, 200, preview)
}
