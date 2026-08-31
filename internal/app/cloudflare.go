package app

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"unicode/utf8"

	"github.com/ArtixSx/razvilka/internal/cloudflareprovider"
)

const cloudflareCopyNotice = "Это только сохранённая копия аккаунта. Регистрация, запуск обхода и изменение маршрутов не выполнялись."

// These endpoints require authentication even before first-run setup, when
// ordinary read-only diagnostics are public. A nil gate must fail closed too.
// A single non-queued operation bounds concurrent parsing/store allocations.
func (a *App) cloudflareAccess(w http.ResponseWriter, r *http.Request, method string) (func(), bool) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != method {
		w.Header().Set("Allow", method)
		methodNotAllowed(w)
		return nil, false
	}
	if a.Security == nil || !a.Security.Authenticated(r) {
		w.Header().Set("WWW-Authenticate", `Bearer realm="RAZVILKA"`)
		http.Error(w, "administrator login is required", http.StatusUnauthorized)
		return nil, false
	}
	if a.Cloudflare == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "Хранилище копий Cloudflare недоступно. Рабочие обходы не затронуты.", "code": "CLOUDFLARE_STORE_UNAVAILABLE"})
		return nil, false
	}
	if !a.cloudflareBusy.CompareAndSwap(false, true) {
		w.Header().Set("Retry-After", "2")
		writeJSON(w, http.StatusTooManyRequests, map[string]any{"error": "Другая операция с копиями Cloudflare ещё выполняется. Повторите через несколько секунд.", "code": "CLOUDFLARE_BUSY"})
		return nil, false
	}
	return func() { a.cloudflareBusy.Store(false) }, true
}

func (a *App) cloudflareAccounts(w http.ResponseWriter, r *http.Request) {
	release, ok := a.cloudflareAccess(w, r, http.MethodGet)
	if !ok {
		return
	}
	defer release()
	accounts, err := a.Cloudflare.List(r.Context())
	if err != nil {
		cloudflareError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"accounts": accounts, "copy_only": true, "limit": cloudflareprovider.MaxAccounts, "max_import_bytes": cloudflareprovider.MaxImportBytes, "note": cloudflareCopyNotice})
}

func (a *App) cloudflareImportPreview(w http.ResponseWriter, r *http.Request) {
	release, ok := a.cloudflareAccess(w, r, http.MethodPost)
	if !ok {
		return
	}
	defer release()
	imported, err := decodeCloudflareImport(w, r, false)
	if err != nil {
		cloudflareError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"account": imported.Preview(), "copy_only": true, "saved": false, "note": "Файл проверен только по структуре и пока не сохранён. Доступность Cloudflare и сервисов не проверялась."})
}

func (a *App) cloudflareImport(w http.ResponseWriter, r *http.Request) {
	release, ok := a.cloudflareAccess(w, r, http.MethodPost)
	if !ok {
		return
	}
	defer release()
	imported, err := decodeCloudflareImport(w, r, true)
	if err != nil {
		cloudflareError(w, err)
		return
	}
	account, err := a.Cloudflare.ImportSnapshot(r.Context(), imported)
	if err != nil {
		cloudflareError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"account": account, "copy_only": true, "saved": true, "note": cloudflareCopyNotice})
}

// The only accepted input is a bounded file's bytes in JSON, not a server path,
// remote URL, hook or automatic migration request. Duplicate/unknown/case-alias
// fields and trailing JSON are rejected with no request content in the error.
func decodeCloudflareImport(w http.ResponseWriter, r *http.Request, save bool) (cloudflareprovider.Import, error) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, cloudflareprovider.MaxImportBytes*6+1024))
	if err != nil || !utf8.Valid(body) {
		return cloudflareprovider.Import{}, cloudflareprovider.ErrImport
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	start, err := decoder.Token()
	if err != nil || start != json.Delim('{') {
		return cloudflareprovider.Import{}, cloudflareprovider.ErrImport
	}
	fields := map[string]string{}
	for decoder.More() {
		token, err := decoder.Token()
		name, valid := token.(string)
		if err != nil || !valid || name != "source_kind" && name != "content" && !(save && name == "confirm") {
			return cloudflareprovider.Import{}, cloudflareprovider.ErrImport
		}
		if _, exists := fields[name]; exists {
			return cloudflareprovider.Import{}, cloudflareprovider.ErrImport
		}
		var value string
		if decoder.Decode(&value) != nil {
			return cloudflareprovider.Import{}, cloudflareprovider.ErrImport
		}
		fields[name] = value
	}
	if end, err := decoder.Token(); err != nil || end != json.Delim('}') {
		return cloudflareprovider.Import{}, cloudflareprovider.ErrImport
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return cloudflareprovider.Import{}, cloudflareprovider.ErrImport
	}
	if save && fields["confirm"] != "SAVE_ACCOUNT_COPY" {
		return cloudflareprovider.Import{}, cloudflareprovider.ErrImport
	}
	return cloudflareprovider.ParseImport(fields["source_kind"], []byte(fields["content"]))
}

func cloudflareError(w http.ResponseWriter, err error) {
	status, code, message := http.StatusServiceUnavailable, "CLOUDFLARE_STORE_UNAVAILABLE", "Не удалось открыть или сохранить копию Cloudflare. Рабочие обходы не изменены."
	if errors.Is(err, cloudflareprovider.ErrImport) {
		status, code, message = http.StatusBadRequest, "CLOUDFLARE_IMPORT_INVALID", "Файл не принят. Проверьте выбранный формат и размер (до 256 КиБ); ссылки, неполные и скрытые ключи не подходят."
	} else if errors.Is(err, cloudflareprovider.ErrBusy) {
		status, code, message = http.StatusConflict, "CLOUDFLARE_STORE_BUSY", "Хранилище занято другой записью или незавершённым импортом. Копии и рабочие обходы не изменены."
	} else if errors.Is(err, cloudflareprovider.ErrCapacity) {
		status, code, message = http.StatusConflict, "CLOUDFLARE_STORE_FULL", "Достигнут лимит: 32 копии аккаунтов. Существующие копии не заменены."
	}
	writeJSON(w, status, map[string]any{"error": message, "code": code})
}
