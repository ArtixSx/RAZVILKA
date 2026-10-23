package app

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/engineconfig"
)

// This endpoint stages a closed desired setting. It cannot launch an engine,
// apply a transaction, change lists or construct argv.
func (a *App) nfqwsFirstStartRecipe(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodGet && r.Method != http.MethodPut {
		methodNotAllowed(w)
		return
	}
	if r.Method == http.MethodPut {
		var input struct {
			Recipe           *engineconfig.NFQWSFirstStartRecipe `json:"recipe"`
			ExpectedRevision *uint64                             `json:"expected_revision"`
		}
		decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&input) != nil || decoder.Decode(new(any)) != io.EOF || input.ExpectedRevision == nil || input.Recipe == nil || !input.Recipe.Valid() {
			http.Error(w, "an exact revision and a known closed NFQWS2 recipe are required", http.StatusBadRequest)
			return
		}
		if err := a.Store.SetNFQWSFirstStartRecipe(*input.ExpectedRevision, *input.Recipe); err != nil {
			if errors.Is(err, config.ErrRevisionChanged) {
				writeJSON(w, http.StatusConflict, map[string]any{"ok": false, "not_started": true, "error": "Настройки изменились. Прочитайте текущую редакцию перед выбором рецепта."})
				return
			}
			http.Error(w, "NFQWS2 recipe draft was not saved", http.StatusInternalServerError)
			return
		}
		a.wakePanelSnapshot()
	}
	cfg := a.Store.Get()
	writeJSON(w, http.StatusOK, map[string]any{
		"recipe": cfg.NFQWSFirstStartRecipe, "applied_recipe": cfg.AppliedNFQWSFirstStartRecipe,
		"revision": cfg.Revision, "pending_changes": cfg.NFQWSFirstStartRecipe != cfg.AppliedNFQWSFirstStartRecipe, "live_applied": false,
		"recipes": []map[string]string{
			{"id": "", "name": "Базовый multisplit · TCP/443", "description": "Исходный закрытый рецепт v1."},
			{"id": string(engineconfig.NFQWSFirstStartStockTLSCircular), "name": "Стандартный TLS circular · TCP/443", "description": "Три исходные TLS-стратегии stock 1.3.1. Доступность сервиса подтверждает только live health после Apply."},
		},
	})
}
