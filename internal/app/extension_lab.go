package app

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"time"

	"github.com/ArtixSx/razvilka/internal/backendprofile"
	"github.com/ArtixSx/razvilka/internal/strategylab"
)

// Every endpoint stays behind the existing auth/origin/admission middleware.
// Rechecking auth here also fences a directly invoked handler in future routing.
func (a *App) extensionAccess(w http.ResponseWriter, r *http.Request) bool {
	w.Header().Set("Cache-Control", "no-store")
	if a.Security == nil || !a.Security.Authenticated(r) {
		writeJSON(w, 401, map[string]any{"error": "Требуется вход."})
		return false
	}
	return true
}
func extensionDecode(w http.ResponseWriter, r *http.Request, dst any) bool {
	d := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	d.DisallowUnknownFields()
	if d.Decode(dst) != nil || d.Decode(&struct{}{}) != io.EOF {
		writeJSON(w, 400, map[string]any{"error": "Некорректный запрос; данные не сохранены."})
		return false
	}
	return true
}
func (a *App) extensionMihomo(w http.ResponseWriter, r *http.Request) {
	if !a.extensionAccess(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	var q struct {
		Content          string                       `json:"content"`
		Options          backendprofile.MihomoOptions `json:"options"`
		Action           string                       `json:"action"`
		Review           string                       `json:"review"`
		Confirm          string                       `json:"confirm"`
		ServiceID        string                       `json:"service_id"`
		ExpectedRevision *uint64                      `json:"expected_revision"`
	}
	if !extensionDecode(w, r, &q) {
		return
	}
	confirm := "BUILD_MIHOMO_CONFIG"
	if q.Action == "validate" {
		confirm = "VALIDATE_MIHOMO_CONFIG"
	}
	if q.Action == "probe" {
		confirm = "PROBE_MIHOMO_SERVICE"
	}
	if (q.Action != "preview" && q.Action != "export" && q.Action != "validate" && q.Action != "probe") || q.Confirm != confirm {
		writeJSON(w, 400, map[string]any{"error": "Подтвердите построение профиля Mihomo."})
		return
	}
	result, e := backendprofile.Mihomo(q.Content, q.Options)
	if e != nil {
		writeJSON(w, 400, map[string]any{"error": "Профиль не преобразован: неподдерживаемые или небезопасные параметры. Они не будут удалены молча."})
		return
	}
	h := sha256.Sum256([]byte(result.Config))
	digest := hex.EncodeToString(h[:])
	if q.Action != "preview" && q.Review != digest {
		writeJSON(w, 409, map[string]any{"error": "Параметры изменились. Повторите предпросмотр."})
		return
	}
	if r.Context().Err() != nil || !a.Security.Authenticated(r) {
		writeJSON(w, 409, map[string]any{"error": "Запрос отменён или сеанс завершён."})
		return
	}
	if q.Action == "probe" {
		a.probeMihomo(w, r, q.Content, q.Options, digest, q.ServiceID, q.ExpectedRevision)
		return
	}
	if q.Action == "validate" {
		ctx, cancel := context.WithTimeout(r.Context(), 12*time.Second)
		defer cancel()
		validation, err := a.validateMihomo(ctx, q.Content, q.Options, digest)
		if err != nil || ctx.Err() != nil || !a.Security.Authenticated(r) {
			writeJSON(w, http.StatusConflict, map[string]any{"error": "Нативная проверка Mihomo не подтверждена. Проверьте установленный компонент и состояние восстановления.", "code": "MIHOMO_NATIVE_VALIDATION_UNCONFIRMED", "live_applied": false, "native_validated": false})
			return
		}
		result.Config = ""
		result.NativeValidated = true
		writeJSON(w, http.StatusOK, map[string]any{"result": result, "validation": validation, "review": digest, "live_applied": false, "draft_persisted": false, "lifecycle": a.runtimeLifecycle("mihomo")})
		return
	}
	if q.Action == "preview" {
		result.Config = ""
	}
	writeJSON(w, 200, map[string]any{"result": result, "review": digest, "live_applied": false, "draft_persisted": false, "lifecycle": a.runtimeLifecycle("mihomo")})
}
func (a *App) extensionHev(w http.ResponseWriter, r *http.Request) {
	if !a.extensionAccess(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	var q struct {
		Options backendprofile.HevOptions `json:"options"`
		Confirm string                    `json:"confirm"`
	}
	if !extensionDecode(w, r, &q) {
		return
	}
	if q.Confirm != "BUILD_HEV_CONFIG" {
		writeJSON(w, 400, map[string]any{"error": "Подтвердите построение профиля HEV."})
		return
	}
	result, e := backendprofile.HevJSON(q.Options)
	if e != nil {
		writeJSON(w, 400, map[string]any{"error": "Недопустимые параметры TUN/HEV."})
		return
	}
	if r.Context().Err() != nil || !a.Security.Authenticated(r) {
		writeJSON(w, 409, map[string]any{"error": "Запрос отменён или сеанс завершён."})
		return
	}
	writeJSON(w, 200, map[string]any{"config": string(result), "live_applied": false, "native_validated": false, "lifecycle": a.runtimeLifecycle("hev"), "note": "JSON совместим с YAML. Экспорт профиля не запускает TUN и не меняет маршруты. Установленный HEV можно выбрать в настройках для следующего запуска; доступность зависит от проверки платформы и маршрута."})
}
func (a *App) strategyPacks(w http.ResponseWriter, r *http.Request) {
	if !a.extensionAccess(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	if a.StrategyLab == nil {
		writeJSON(w, 503, map[string]any{"error": "Лаборатория стратегий недоступна."})
		return
	}
	var q struct {
		Action       string   `json:"action"`
		Content      string   `json:"content"`
		Signed       bool     `json:"signed"`
		Review       string   `json:"review"`
		Confirm      string   `json:"confirm"`
		CandidateIDs []string `json:"candidate_ids"`
	}
	if !extensionDecode(w, r, &q) {
		return
	}
	if q.Action == "export" {
		if q.Confirm != "EXPORT_STRATEGIES" {
			writeJSON(w, 400, map[string]any{"error": "Подтвердите экспорт параметров."})
			return
		}
		data, e := a.StrategyLab.ExportPack(q.CandidateIDs)
		if e != nil {
			writeJSON(w, 400, map[string]any{"error": "Выберите 1–64 стратегии из поддержанного безопасного подмножества. Файлы, Lua-код и системные параметры не экспортируются."})
			return
		}
		writeJSON(w, 200, map[string]any{"content": string(data), "live_applied": false})
		return
	}
	if q.Action != "preview" && q.Action != "import" {
		writeJSON(w, 400, map[string]any{"error": "Неизвестное действие."})
		return
	}
	if len(q.CandidateIDs) != 0 {
		writeJSON(w, 400, map[string]any{"error": "Смешаны разные действия."})
		return
	}
	review, e := strategylab.ReviewPack([]byte(q.Content), q.Signed, a.StrategyLab.PackKeys, time.Now())
	if e != nil {
		writeJSON(w, 400, map[string]any{"error": "Пакет не принят: формат, срок, параметры или подпись не подтверждены. Ключ издателя должен быть заранее настроен владельцем."})
		return
	}
	if q.Action == "preview" {
		writeJSON(w, 200, review)
		return
	}
	if q.Confirm != "IMPORT_STRATEGY_CANDIDATES" || q.Review != review.SHA256 {
		writeJSON(w, 409, map[string]any{"error": "Повторите предпросмотр и подтвердите добавление кандидатов."})
		return
	}
	if r.Context().Err() != nil || !a.Security.Authenticated(r) {
		writeJSON(w, 409, map[string]any{"error": "Запрос отменён или сеанс завершён."})
		return
	}
	result, e := a.StrategyLab.ImportPack([]byte(q.Content), q.Signed, q.Review)
	if e != nil {
		writeJSON(w, 409, map[string]any{"error": "Импорт не завершён: устаревшая версия, другой отпечаток или ошибка хранилища. Повторите просмотр состояния."})
		return
	}
	writeJSON(w, 200, result)
}

func (a *App) builtinStrategyPack(w http.ResponseWriter, r *http.Request) {
	if !a.extensionAccess(w, r) {
		return
	}
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	writeJSON(w, 200, map[string]any{"content": string(strategylab.BuiltinPack(time.Now())), "live_applied": false, "note": "Примеры из закреплённого upstream, не локально проверенные стратегии. Голос/UDP Discord не импортируется упрощённой заменой."})
}
