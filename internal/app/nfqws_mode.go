package app

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/ArtixSx/razvilka/internal/catalog"
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

// nfqwsDiscordRepair stages the Discord voice repair into the NFQWS2 draft
// ("additional strategies") when the reviewed configuration lacks it. The
// ordinary reviewed Apply validates and activates the draft.
func (a *App) nfqwsDiscordRepair(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if a.EngineConfigs == nil || a.Store == nil {
		writeJSON(w, 503, map[string]any{"error": "Редактор конфигурации недоступен."})
		return
	}
	if r.Method != http.MethodPut {
		methodNotAllowed(w)
		return
	}
	var q struct {
		Review   string  `json:"review"`
		Revision *uint64 `json:"config_revision"`
		Confirm  string  `json:"confirm"`
	}
	d := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
	d.DisallowUnknownFields()
	if d.Decode(&q) != nil || d.Decode(&struct{}{}) != io.EOF || q.Revision == nil || q.Confirm != "STAGE_DISCORD_REPAIR" {
		writeJSON(w, 400, map[string]any{"error": "Подтвердите добавление ремонта Discord."})
		return
	}
	if a.Store.Get().Revision != *q.Revision {
		writeJSON(w, 409, map[string]any{"error": "Настройки изменились. Перечитайте конфигурацию."})
		return
	}
	v, e := a.EngineConfigs.StageNFQWSDiscordRepair(r.Context(), q.Review)
	if e != nil {
		code, message := 400, "Ремонт Discord не добавлен: конфигурация нестандартная или изменилась. Перечитайте её."
		switch {
		case errors.Is(e, engineconfig.ErrNFQWSModeChanged):
			code = 409
		case errors.Is(e, engineconfig.ErrDiscordRepairPorts):
			message = "Ремонт Discord не добавлен: в списке UDP-портов NFQWS2 нет места для портов голоса (предел iptables — 15). Объедините порты в диапазоны в редакторе."
		}
		writeJSON(w, code, map[string]any{"error": message, "live_applied": false})
		return
	}
	writeJSON(w, 200, map[string]any{"mode": v, "live_applied": false})
}

// nfqwsExclusions lists the package's default exclusions, so the panel can
// show which entries of exclude.list the owner added or removed.
func (a *App) nfqwsExclusions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]any{"stock": catalog.NFQWS2StockExclusions(), "package_version": "1.3.1"})
}
