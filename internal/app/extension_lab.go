package app

import (
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
		Content string                       `json:"content"`
		Options backendprofile.MihomoOptions `json:"options"`
		Action  string                       `json:"action"`
		Review  string                       `json:"review"`
		Confirm string                       `json:"confirm"`
	}
	if !extensionDecode(w, r, &q) {
		return
	}
	if (q.Action != "preview" && q.Action != "export") || q.Confirm != "BUILD_MIHOMO_CONFIG" {
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
	if q.Action == "export" && q.Review != digest {
		writeJSON(w, 409, map[string]any{"error": "Параметры изменились. Повторите предпросмотр."})
		return
	}
	if r.Context().Err() != nil || !a.Security.Authenticated(r) {
		writeJSON(w, 409, map[string]any{"error": "Запрос отменён или сеанс завершён."})
		return
	}
	if q.Action == "preview" {
		result.Config = ""
	}
	writeJSON(w, 200, map[string]any{"result": result, "review": digest, "live_applied": false, "draft_persisted": false})
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
	writeJSON(w, 200, map[string]any{"config": string(result), "live_applied": false, "native_validated": false, "note": "JSON совместим с YAML. Профиль не создаёт TUN и не меняет маршруты до отдельного запуска. В RAZVILKA выбранный HEV-адаптер пока включается только на программном стенде."})
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
