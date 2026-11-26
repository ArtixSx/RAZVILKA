package app

import (
	"net/http"

	"github.com/ArtixSx/razvilka/internal/sources"
)

const sourceOfflineCatalogPath = "/api/v1/sources/offline"

// This DTO describes a saved-data view, never source readiness or permission
// to refresh/apply. The existing source-list response remains unchanged.
type sourceOfflineCatalogView struct {
	Offline  bool            `json:"offline"`
	ReadOnly bool            `json:"read_only"`
	Sources  []sources.State `json:"sources"`
}

// Register behind the existing security and operation middleware. Catalogue
// readback only copies memory; it does not fetch, renew TTL or write settings.
func (a *App) sourceOfflineCatalog(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		methodNotAllowed(w)
		return
	}
	rows := make([]sources.State, 0)
	if a.Sources != nil {
		rows = a.Sources.OfflineCatalog()
	}
	writeJSON(w, http.StatusOK, sourceOfflineCatalogView{Offline: true, ReadOnly: true, Sources: rows})
}
