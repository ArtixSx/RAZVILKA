package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/dnscontrol"
)

type serviceDNSComparer interface {
	CompareServiceDNSGuarded(context.Context, []string, string, func(context.Context) error) (dnscontrol.ServiceDNSComparison, error)
}

var errDNSCompareUnauthorized = errors.New("service DNS comparison authentication expired")

func writeDNSCompareFailure(w http.ResponseWriter, err error) {
	status, code, message := http.StatusServiceUnavailable, "DNS_COMPARE_UNAVAILABLE", "DNS-сравнение сейчас недоступно. Повторите позже."
	switch {
	case errors.Is(err, errDNSCompareUnauthorized):
		status, code, message = http.StatusUnauthorized, "DNS_COMPARE_AUTH_REQUIRED", "Сеанс завершён. Войдите снова перед сравнением DNS."
	case errors.Is(err, context.Canceled):
		status, code, message = http.StatusRequestTimeout, "DNS_COMPARE_CANCELED", "Сравнение DNS отменено. Завершённого результата нет."
	case errors.Is(err, context.DeadlineExceeded):
		status, code, message = http.StatusGatewayTimeout, "DNS_COMPARE_TIMEOUT", "Истекло время сравнения DNS. Завершённого результата нет."
	case errors.Is(err, dnscontrol.ErrServiceDNSChanged):
		status, code, message = http.StatusConflict, "DNS_COMPARE_CHANGED", "Сервис, DNS или настройки изменились. Обновите состояние и повторите сравнение."
	case errors.Is(err, dnscontrol.ErrServiceDNSInvalid):
		status, code, message = http.StatusBadRequest, "DNS_COMPARE_INVALID", "Выберите сервис с публичным DNS-именем и от одного до трёх настроенных публичных DoH-профилей."
	}
	writeJSON(w, status, map[string]any{"ok": false, "code": code, "error": message, "service_verified": false, "live_applied": false})
}

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
		ConfigRevision *uint64  `json:"config_revision"`
		Confirm        string   `json:"confirm"`
	}
	d := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
	d.DisallowUnknownFields()
	if d.Decode(&q) != nil || d.Decode(&struct{}{}) != io.EOF || q.Confirm != "COMPARE_SERVICE_DNS" || q.ConfigRevision == nil {
		writeJSON(w, 400, map[string]any{"error": "Выберите сервис, DNS и подтвердите тестовые DNS-запросы."})
		return
	}
	cfg := a.Store.Get()
	if cfg.Revision != *q.ConfigRevision {
		writeDNSCompareFailure(w, dnscontrol.ErrServiceDNSChanged)
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
	// Keep an immutable image: catalog entries include slices that may otherwise
	// alias a later update and make a shallow snapshot compare equal to itself.
	serviceImage, err := json.Marshal(selected)
	if err != nil {
		writeDNSCompareFailure(w, err)
		return
	}
	start := time.Now()
	guard := func(ctx context.Context) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if !a.Security.Authenticated(r) {
			return errDNSCompareUnauthorized
		}
		if a.Store.Get().Revision != cfg.Revision {
			return dnscontrol.ErrServiceDNSChanged
		}
		for _, current := range a.catalogSnapshot().Services {
			if current.ID == selected.ID {
				image, err := json.Marshal(current)
				if err == nil && bytes.Equal(image, serviceImage) {
					return nil
				}
				break
			}
		}
		return dnscontrol.ErrServiceDNSChanged
	}
	comparer := a.dnsServiceComparer
	if comparer == nil {
		comparer = a.DNS
	}
	if err := guard(r.Context()); err != nil {
		writeDNSCompareFailure(w, err)
		return
	}
	result, err := comparer.CompareServiceDNSGuarded(r.Context(), q.ProfileIDs, u.Hostname(), guard)
	if err == nil {
		err = guard(r.Context())
	}
	if err != nil {
		writeDNSCompareFailure(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "service_id": q.ServiceID, "config_revision": cfg.Revision, "result": result, "duration_ms": time.Since(start).Milliseconds(), "live_applied": false})
}
