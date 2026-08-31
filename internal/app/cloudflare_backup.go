package app

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"unicode/utf8"

	"github.com/ArtixSx/razvilka/internal/cloudflareprovider"
	"github.com/ArtixSx/razvilka/internal/privatebackup"
)

// Bound all HTTP backup encryption/decryption, including legacy router backups,
// before allocating input or starting PBKDF2. Never queue requests on a router.
func (a *App) backupOperation(w http.ResponseWriter) (func(), bool) {
	w.Header().Set("Cache-Control", "no-store")
	if !a.privateBackupBusy.CompareAndSwap(false, true) {
		w.Header().Set("Retry-After", "2")
		writeJSON(w, http.StatusTooManyRequests, map[string]any{"error": "Другая операция с резервной копией ещё выполняется. Подождите и повторите.", "code": "PRIVATE_BACKUP_BUSY"})
		return nil, false
	}
	return func() { a.privateBackupBusy.Store(false) }, true
}

func (a *App) cloudflareBackupAccess(w http.ResponseWriter, r *http.Request) (func(), bool) {
	release, ok := a.cloudflareAccess(w, r, http.MethodPost)
	if !ok {
		return nil, false
	}
	cryptoRelease, ok := a.backupOperation(w)
	if !ok {
		release()
		return nil, false
	}
	return func() { cryptoRelease(); release() }, true
}

func (a *App) cloudflareBackupExport(w http.ResponseWriter, r *http.Request) {
	release, ok := a.cloudflareBackupAccess(w, r)
	if !ok {
		return
	}
	defer release()
	request, err := decodeCloudflareBackup(w, r, "export")
	if err != nil {
		cloudflareError(w, err)
		return
	}
	envelope, err := a.Cloudflare.Backup(r.Context(), request.Password, Version)
	request.Password = ""
	if err != nil {
		cloudflareError(w, err)
		return
	}
	w.Header().Set("Content-Disposition", `attachment; filename="razvilka-cloudflare-copies.json"`)
	writeJSON(w, http.StatusOK, envelope)
}

func (a *App) cloudflareBackupPreview(w http.ResponseWriter, r *http.Request) {
	release, ok := a.cloudflareBackupAccess(w, r)
	if !ok {
		return
	}
	defer release()
	request, err := decodeCloudflareBackup(w, r, "preview")
	if err != nil {
		cloudflareError(w, err)
		return
	}
	review, err := a.Cloudflare.PreviewBackup(r.Context(), request.Envelope, request.Password)
	request.Password = ""
	if err != nil {
		cloudflareError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"review": review, "copy_only": true, "saved": false, "note": "Архив проверен. Новые копии будут добавлены; существующие не заменяются. Рабочие профили и маршруты не изменятся."})
}

func (a *App) cloudflareBackupRestore(w http.ResponseWriter, r *http.Request) {
	release, ok := a.cloudflareBackupAccess(w, r)
	if !ok {
		return
	}
	defer release()
	request, err := decodeCloudflareBackup(w, r, "restore")
	if err != nil {
		cloudflareError(w, err)
		return
	}
	accounts, err := a.Cloudflare.RestoreReviewedBackup(r.Context(), request.Envelope, request.Password, request.PreviewDigest)
	request.Password = ""
	if err != nil {
		cloudflareError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"accounts": accounts, "copy_only": true, "saved": true, "note": cloudflareCopyNotice})
}

type cloudflareBackupRequest struct {
	Password      string                 `json:"password"`
	Envelope      privatebackup.Envelope `json:"envelope"`
	Confirm       string                 `json:"confirm"`
	PreviewDigest string                 `json:"preview_digest"`
}

// Reject unknown/duplicate/case-alias keys at both object boundaries. The body
// and ciphertext allocations are capped before any expensive crypto operation.
func strictBackupObject(raw []byte, allowed ...string) (map[string]json.RawMessage, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	start, err := decoder.Token()
	if err != nil || start != json.Delim('{') {
		return nil, cloudflareprovider.ErrBackup
	}
	fields := map[string]json.RawMessage{}
	for decoder.More() {
		token, err := decoder.Token()
		name, valid := token.(string)
		known := false
		for _, key := range allowed {
			if key == name {
				known = true
			}
		}
		if err != nil || !valid || !known {
			return nil, cloudflareprovider.ErrBackup
		}
		if _, exists := fields[name]; exists {
			return nil, cloudflareprovider.ErrBackup
		}
		var value json.RawMessage
		if decoder.Decode(&value) != nil || bytes.Equal(value, []byte("null")) {
			return nil, cloudflareprovider.ErrBackup
		}
		fields[name] = value
	}
	if end, err := decoder.Token(); err != nil || end != json.Delim('}') {
		return nil, cloudflareprovider.ErrBackup
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return nil, cloudflareprovider.ErrBackup
	}
	return fields, nil
}

func decodeCloudflareBackup(w http.ResponseWriter, r *http.Request, action string) (cloudflareBackupRequest, error) {
	var request cloudflareBackupRequest
	allowed := []string{"password"}
	limit := int64(4096)
	if action != "export" {
		allowed = append(allowed, "envelope")
		limit = privatebackup.MaxEnvelope * 2
	}
	if action == "restore" {
		allowed = append(allowed, "confirm", "preview_digest")
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, limit))
	if err != nil || !utf8.Valid(body) {
		return request, cloudflareprovider.ErrBackup
	}
	fields, err := strictBackupObject(body, allowed...)
	if err != nil || len(fields) != len(allowed) {
		return request, cloudflareprovider.ErrBackup
	}
	if action != "export" {
		if _, err := strictBackupObject(fields["envelope"], "kind", "schema", "app_version", "created_at", "kdf", "iterations", "cipher", "salt", "nonce", "ciphertext"); err != nil {
			return request, err
		}
	}
	if json.Unmarshal(body, &request) != nil || len(request.Password) < 12 || len(request.Password) > 256 {
		return cloudflareBackupRequest{}, cloudflareprovider.ErrBackup
	}
	if action == "restore" && (request.Confirm != "RESTORE_ACCOUNT_COPIES" || len(request.PreviewDigest) != 64) {
		return cloudflareBackupRequest{}, cloudflareprovider.ErrReview
	}
	return request, nil
}
