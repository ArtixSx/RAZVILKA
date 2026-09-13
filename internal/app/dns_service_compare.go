package app

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/ArtixSx/razvilka/internal/catalog"
)

// This endpoint compares DNS data only. It cannot change routes, renew WARP
// credentials, publish observations, or feed PASS into the node checker.
func (a *App) dnsServiceCompare(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	if a.Security == nil || !a.Security.Authenticated(r) {
		writeJSON(w, 401, map[string]any{"error": "Требуется авторизация."})
		return
	}
	if a.DNS == nil || a.Store == nil {
		writeJSON(w, 503, map[string]any{"error": "DNS или конфигурация недоступны."})
		return
	}
	var q struct {
		ServiceID      string   `json:"service_id"`
		ProfileIDs     []string `json:"profile_ids"`
		ConfigRevision uint64   `json:"config_revision"`
		Confirm        string   `json:"confirm"`
	}
	d := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
	d.DisallowUnknownFields()
	if d.Decode(&q) != nil || d.Decode(&struct{}{}) != io.EOF || q.Confirm != "COMPARE_SERVICE_DNS" {
		writeJSON(w, 400, map[string]any{"error": "Выберите сервис, DNS и подтвердите тестовые DNS-запросы."})
		return
	}
	cfg := a.Store.Get()
	if cfg.Revision != q.ConfigRevision {
		writeJSON(w, 409, map[string]any{"error": "Редакция настроек изменилась. Обновите состояние."})
		return
	}
	// A system-path DNS query is not a probe inside an enforced VPN. Do not
	// leak a protected service name merely because the UI requested a comparison.
	if p, ok := cfg.ServicePolicies[q.ServiceID]; ok && p.TerminalAction != "direct" {
		writeJSON(w, 409, map[string]any{"code": "DNS_PROBE_PATH_POLICY", "error": "У сервиса закреплена политика без прямого резерва. Сравнение через защищённый путь ещё не реализовано; обычный DNS-запрос не отправлен."})
		return
	}
	var selected *catalog.Service
	for _, s := range a.catalogSnapshot().Services {
		if s.ID == q.ServiceID {
			v := s
			selected = &v
			break
		}
	}
	if selected == nil {
		writeJSON(w, 404, map[string]any{"error": "Сервис не найден."})
		return
	}
	target := selected.ProbeURL
	if target == "" {
		for _, p := range selected.Probes {
			if p.Required && p.URL != "" {
				target = p.URL
				break
			}
		}
	}
	u, err := url.Parse(target)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil {
		writeJSON(w, 400, map[string]any{"error": "У сервиса нет допустимого HTTPS-сценария."})
		return
	}
	start := time.Now()
	result, err := a.DNS.CompareServiceDNS(r.Context(), q.ProfileIDs, u.Hostname())
	if err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error(), "service_verified": false, "live_applied": false})
		return
	}
	if a.Store.Get().Revision != cfg.Revision {
		writeJSON(w, 409, map[string]any{"error": "Настройки изменились во время сравнения. Результат не используется.", "live_applied": false})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "service_id": q.ServiceID, "result": result, "duration_ms": time.Since(start).Milliseconds(), "live_applied": false})
}
