package app

import (
	"encoding/json"
	"io"
	"net/http"
	"unicode/utf8"

	"github.com/ArtixSx/razvilka/internal/cloudflareprovider"
)

func (a *App) cloudflareLegacySources(w http.ResponseWriter, r *http.Request) {
	if !a.cloudflareAuth(w, r, http.MethodGet) {
		return
	}
	// Immutable startup metadata only: no secret parsing, filesystem scan or KDF.
	locations := []cloudflareprovider.LegacyLocation{}
	if a.CloudflareLegacy != nil {
		locations = a.CloudflareLegacy.Locations()
	}
	writeJSON(w, http.StatusOK, map[string]any{"sources": locations, "copy_only": true, "note": "Это известные расположения, а не список найденных или работающих обходов. Файл читается только после вашего выбора."})
}

func (a *App) cloudflareLegacyPreview(w http.ResponseWriter, r *http.Request) {
	release, ok := a.cloudflareAccess(w, r, http.MethodPost)
	if !ok {
		return
	}
	defer release()
	request, err := decodeLegacyRequest(w, r, false)
	if err != nil {
		cloudflareError(w, err)
		return
	}
	if a.CloudflareLegacy == nil {
		cloudflareError(w, cloudflareprovider.ErrLegacySource)
		return
	}
	review, err := a.CloudflareLegacy.Preview(r.Context(), request.SourceID)
	if err != nil {
		cloudflareError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"review": review, "copy_only": true, "saved": false, "note": "Проверена структура выбранного файла. Исходный файл, запущенный обход и маршруты не изменены."})
}

func (a *App) cloudflareLegacyCopy(w http.ResponseWriter, r *http.Request) {
	release, ok := a.cloudflareAccess(w, r, http.MethodPost)
	if !ok {
		return
	}
	defer release()
	request, err := decodeLegacyRequest(w, r, true)
	if err != nil {
		cloudflareError(w, err)
		return
	}
	if a.CloudflareLegacy == nil {
		cloudflareError(w, cloudflareprovider.ErrLegacySource)
		return
	}
	account, err := a.CloudflareLegacy.Copy(r.Context(), a.Cloudflare, request.SourceID, request.Digest)
	if err != nil {
		cloudflareError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"account": account, "copy_only": true, "saved": true, "note": cloudflareCopyNotice})
}

type legacyRequest struct {
	SourceID string `json:"source_id"`
	Digest   string `json:"review_digest"`
	Confirm  string `json:"confirm"`
}

func decodeLegacyRequest(w http.ResponseWriter, r *http.Request, copy bool) (legacyRequest, error) {
	var request legacyRequest
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 2048))
	if err != nil || !utf8.Valid(body) {
		return request, cloudflareprovider.ErrLegacySource
	}
	allowed := []string{"source_id"}
	if copy {
		allowed = append(allowed, "review_digest", "confirm")
	}
	fields, err := strictBackupObject(body, allowed...)
	if err != nil || len(fields) != len(allowed) || json.Unmarshal(body, &request) != nil || len(request.SourceID) == 0 || len(request.SourceID) > 48 {
		return legacyRequest{}, cloudflareprovider.ErrLegacySource
	}
	if copy && (request.Confirm != "COPY_LEGACY_ACCOUNT" || len(request.Digest) != 64) {
		return legacyRequest{}, cloudflareprovider.ErrLegacyChanged
	}
	return request, nil
}
