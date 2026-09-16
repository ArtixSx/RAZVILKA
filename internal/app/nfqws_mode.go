package app

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/ArtixSx/razvilka/internal/engineconfig"
)

// Only edits a reviewed private draft; mode discovery is an explicit separate
// consent. Does not execute the shell config, install components or apply routes.
func (a *App) nfqwsSetupMode(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if a.EngineConfigs == nil || a.Store == nil {
		writeJSON(w, 503, map[string]any{"error": "Редактор конфигурации недоступен."})
		return
	}
	if r.Method == http.MethodGet {
		v, e := a.EngineConfigs.NFQWSMode()
		if e != nil {
			writeJSON(w, 409, map[string]any{"error": "Конфигурация нестандартная или недоступна. Используйте основной редактор."})
			return
		}
		writeJSON(w, 200, v)
		return
	}
	if r.Method != http.MethodPut {
		methodNotAllowed(w)
		return
	}
	var q struct {
		Mode     string  `json:"mode"`
		Review   string  `json:"review"`
		Allow    bool    `json:"allow_discovery"`
		Revision *uint64 `json:"config_revision"`
		Confirm  string  `json:"confirm"`
	}
	d := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
	d.DisallowUnknownFields()
	if d.Decode(&q) != nil || d.Decode(&struct{}{}) != io.EOF || q.Revision == nil || q.Confirm != "STAGE_NFQWS_MODE" {
		writeJSON(w, 400, map[string]any{"error": "Подтвердите параметры режима."})
		return
	}
	if a.Store.Get().Revision != *q.Revision {
		writeJSON(w, 409, map[string]any{"error": "Настройки изменились. Перечитайте конфигурацию."})
		return
	}
	v, e := a.EngineConfigs.StageNFQWSMode(r.Context(), q.Mode, q.Review, q.Allow)
	if e != nil {
		code := 400
		if errors.Is(e, engineconfig.ErrNFQWSModeChanged) {
			code = 409
		}
		writeJSON(w, code, map[string]any{"error": "Режим не сохранён: источник изменился, не поддержан или согласие не получено.", "live_applied": false})
		return
	}
	writeJSON(w, 200, map[string]any{"mode": v, "live_applied": false})
}
