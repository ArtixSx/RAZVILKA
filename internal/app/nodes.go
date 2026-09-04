package app

import (
	"net/http"
	"time"
)

func (a *App) nodeList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	if a.Nodes == nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"available": false, "nodes": []any{}, "sources": []any{},
			"note": "Приватное хранилище узлов недоступно. Рабочие маршруты не изменены.",
		})
		return
	}
	snapshot, err := a.Nodes.Snapshot(r.Context(), time.Now())
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{
			"available": false, "nodes": []any{}, "sources": []any{},
			"error": "Не удалось прочитать приватное хранилище узлов. Рабочие маршруты не изменены.",
		})
		return
	}
	quarantined, expired := 0, 0
	for _, node := range snapshot.Nodes {
		if node.State == "expired" {
			expired++
		} else {
			quarantined++
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"available": true, "generation": snapshot.Generation,
		"nodes": snapshot.Nodes, "sources": snapshot.Sources,
		"counts": map[string]int{"total": len(snapshot.Nodes), "quarantined": quarantined, "expired": expired, "selectable": 0},
		"note":   "Узлы сохранены локально, но ещё не проверены и поэтому недоступны для маршрутов.",
	})
}
