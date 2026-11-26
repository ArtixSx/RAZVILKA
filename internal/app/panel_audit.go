package app

import (
	"net/http"
	"strconv"
)

const panelAuditPath = "/api/v1/audit/current"

// No Store, journal read, network command or admission is needed to display
// persisted action history while Apply/recovery owns the router transaction.
func (a *App) panelAudit(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	writeJSON(w, http.StatusOK, a.Audit.Cached(limit))
}
