package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"strings"
	"time"

	"github.com/ArtixSx/razvilka/internal/awgprofile"
	"github.com/ArtixSx/razvilka/internal/dataplane"
)

func (a *App) awgInventory(ctx context.Context) awgprofile.Capabilities {
	if a.AWGCapabilityProbe != nil {
		return a.AWGCapabilityProbe(ctx)
	}
	return awgprofile.Detect(ctx)
}

type awgRequest struct {
	Content        string `json:"content"`
	ExpectedSHA256 string `json:"expected_sha256"`
	BaseSHA256     string `json:"base_sha256"`
	Confirm        string `json:"confirm"`
	ServiceID      string `json:"service_id"`
}

// Only local authenticated users can inspect private files or stage a draft.
// The UI sees redacted analysis; no private key or profile is returned here.
func (a *App) amneziaAPI(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if a.Security == nil || !a.Security.Authenticated(r) {
		writeJSON(w, 401, map[string]any{"error": "Требуется авторизация."})
		return
	}
	if a.EngineConfigs == nil {
		writeJSON(w, 503, map[string]any{"error": "Хранилище конфигураций недоступно."})
		return
	}
	action := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/v1/amneziawg"), "/")
	if action == "" && r.Method == http.MethodGet {
		data, err := a.EngineConfigs.ReadExpert("amneziawg", "main")
		if err != nil {
			writeJSON(w, 503, map[string]any{"error": "Приватное хранилище профиля недоступно."})
			return
		}
		out := map[string]any{"source": data.Source, "base_sha256": data.SHA256, "capabilities": a.awgInventory(r.Context()), "syntax_valid": false, "network_verified": false, "generator": "local-cloudflare-provider", "note": "AWG 3.1 требует совместимый сервер. WARP — отдельный профиль, не AWG 3.1."}
		if data.Content != "" {
			p, err := awgprofile.Parse(data.Content)
			if err != nil {
				out["issue"] = awgIssue(err)
			} else {
				out["syntax_valid"] = true
				out["profile"] = p.Public()
				out["blockers"] = awgprofile.Check(p.Public(), out["capabilities"].(awgprofile.Capabilities))
			}
		}
		writeJSON(w, 200, out)
		return
	}
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	if action != "preview" && action != "import" && action != "canary" {
		http.NotFound(w, r)
		return
	}
	var q awgRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 512<<10))
	dec.DisallowUnknownFields()
	if dec.Decode(&q) != nil || dec.Decode(&struct{}{}) != io.EOF {
		writeJSON(w, 400, map[string]any{"error": "Неверное тело запроса."})
		return
	}
	if action == "canary" {
		a.amneziaCanary(w, r, q)
		return
	}
	if q.ServiceID != "" {
		writeJSON(w, 400, map[string]any{"error": "Импорт не выбирает сервис и не применяет маршрут."})
		return
	}
	p, err := awgprofile.Parse(q.Content)
	if err != nil {
		writeJSON(w, 400, map[string]any{"error": "Профиль отклонён.", "issue": awgIssue(err)})
		return
	}
	current, err := a.EngineConfigs.ReadExpert("amneziawg", "main")
	if err != nil {
		writeJSON(w, 503, map[string]any{"error": "Не удалось сверить текущую редакцию профиля."})
		return
	}
	caps := a.awgInventory(r.Context())
	if action == "preview" {
		writeJSON(w, 200, map[string]any{"preview": p.Public(), "base_sha256": current.SHA256, "capabilities": caps, "blockers": awgprofile.Check(p.Public(), caps), "live_applied": false})
		return
	}
	if q.Confirm != "STAGE_AWG_PROFILE" || q.ExpectedSHA256 != p.Public().SHA256 {
		writeJSON(w, 409, map[string]any{"error": "Подтвердите именно показанный профиль.", "not_started": true})
		return
	}
	if q.BaseSHA256 != current.SHA256 {
		writeJSON(w, 409, map[string]any{"error": "Конфигурация изменилась. Повторите предпросмотр.", "not_started": true})
		return
	}
	// An unsupported draft may be stored for later installation, but canary and
	// live activation independently enforce actual runtime capabilities.
	if _, err := a.EngineConfigs.Stage("amneziawg", "main", p.Config()); err != nil {
		writeJSON(w, 409, map[string]any{"error": "Черновик не сохранён; повторите чтение состояния."})
		return
	}
	writeJSON(w, 200, map[string]any{"staged": true, "live_applied": false, "profile": p.Public(), "blockers": awgprofile.Check(p.Public(), caps), "note": "Сохранён только черновик. Маршруты, DNS и peer не менялись."})
}
func awgIssue(err error) awgprofile.Issue {
	var i awgprofile.Issue
	if errors.As(err, &i) {
		return i
	}
	return awgprofile.Issue{Code: "AWG_INVALID", Message: "Профиль не прошёл безопасную проверку."}
}
func (a *App) amneziaCanary(w http.ResponseWriter, r *http.Request, q awgRequest) {
	if q.Confirm != "PROBE_AWG_PROFILE" || q.ServiceID == "" || q.Content != "" {
		writeJSON(w, 400, map[string]any{"error": "Выберите сервис и подтвердите изолированную проверку."})
		return
	}
	if a.Store == nil {
		writeJSON(w, 409, map[string]any{"error": "Настройки приложения недоступны."})
		return
	}
	cfg := a.Store.Get()
	if cfg.SafeMode || cfg.ServiceControl.Stopped {
		writeJSON(w, 409, map[string]any{"error": "Safe Mode или общая остановка запрещают временные сетевые изменения."})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 110*time.Second)
	defer cancel()
	network, err := a.freshNetworkProfile(ctx)
	if err != nil || network == "" {
		writeJSON(w, 409, map[string]any{"error": "Текущая сеть не подтверждена. Повторите проверку позже.", "live_applied": false})
		return
	}
	current, err := a.EngineConfigs.ReadExpert("amneziawg", "main")
	if err != nil || current.SHA256 != q.BaseSHA256 {
		writeJSON(w, 409, map[string]any{"error": "Редакция профиля изменилась."})
		return
	}
	p, err := awgprofile.Parse(current.Content)
	if err != nil {
		writeJSON(w, 400, map[string]any{"issue": awgIssue(err)})
		return
	}
	caps := a.awgInventory(ctx)
	if issues := awgprofile.Check(p.Public(), caps); len(issues) > 0 {
		writeJSON(w, 409, map[string]any{"error": "Исполнитель не поддерживает профиль.", "blockers": issues})
		return
	}
	if a.Dataplane == nil || !a.Dataplane.CanaryCapable("amneziawg") {
		writeJSON(w, 503, map[string]any{"error": "Изолированный адаптер AmneziaWG недоступен."})
		return
	}
	catalogHash := applyReviewHash(a.catalogSnapshot())
	plan, err := a.tunnelProbePlan("amneziawg", q.ServiceID, current.Source == "staged")
	if err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	// Each non-live transaction phase must still refer to this exact profile,
	// service definition, runtime and network. The operation gate serializes
	// HTTP edits; this guard also fences external changes and canceled intent.
	guard := func(c context.Context) error {
		if c.Err() != nil {
			return c.Err()
		}
		if !reflect.DeepEqual(a.Store.Get(), cfg) || applyReviewHash(a.catalogSnapshot()) != catalogHash {
			return dataplane.ErrReviewChanged
		}
		latest, err := a.EngineConfigs.ReadExpert("amneziawg", "main")
		if err != nil || latest.SHA256 != current.SHA256 || latest.Source != current.Source {
			return dataplane.ErrReviewChanged
		}
		if !reflect.DeepEqual(a.awgInventory(c), caps) {
			return dataplane.ErrReviewChanged
		}
		observed, err := a.freshNetworkProfile(c)
		if err != nil || observed != network {
			return dataplane.ErrNetworkChanged
		}
		return c.Err()
	}
	ctx = dataplane.WithReviewGuard(ctx, guard)
	started := time.Now()
	err = a.Dataplane.ProbeCandidate(ctx, plan, "amneziawg")
	if err != nil {
		if errors.Is(err, dataplane.ErrReviewChanged) || errors.Is(err, dataplane.ErrNetworkChanged) || errors.Is(err, context.Canceled) {
			writeJSON(w, 409, map[string]any{"ok": false, "code": "AWG_CANARY_CHANGED", "error": "Профиль, сервис, исполнитель, сеть или разрешения изменились. Повторите проверку актуального состояния.", "live_applied": false})
			return
		}
		writeJSON(w, 502, map[string]any{"ok": false, "code": "AWG_CANARY_FAILED", "error": "Изолированная проверка не подтверждена. Кандидат не применяется; состояние очистки смотрите в диагностике.", "duration_ms": time.Since(started).Milliseconds(), "live_applied": false})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "service_id": q.ServiceID, "test_level": "isolated-web", "duration_ms": time.Since(started).Milliseconds(), "live_applied": false, "note": "Подтверждён изолированный веб-сценарий, не все функции приложения и не LAN-трафик. Apply — отдельная транзакция."})
}
func (a *App) tunnelProbePlan(engineID, serviceID string, draft bool) (dataplane.Plan, error) {
	for _, s := range a.catalogSnapshot().Services {
		if s.ID != serviceID {
			continue
		}
		url := s.ProbeURL
		if url == "" {
			for _, p := range s.Probes {
				if p.Required && p.URL != "" {
					url = p.URL
					break
				}
			}
		}
		if url == "" {
			return dataplane.Plan{}, errors.New("У сервиса нет поддержанного веб-сценария.")
		}
		p := dataplane.Plan{SchemaVersion: dataplane.SchemaVersion, PlanID: fmt.Sprintf("tunnel-probe-%d", time.Now().UnixNano()), Adapters: []string{engineID}, Routes: []dataplane.Route{{ServiceID: s.ID, ServiceName: s.Name, Selected: engineID, Resolved: engineID, Domains: append([]string(nil), s.Domains...), CIDRs: append([]string(nil), s.CIDRs...), SourceRefs: append([]string(nil), s.SourceRefs...), ProbeURL: url}}}
		if draft {
			p.EngineDrafts = []string{engineID + "/main"}
		}
		return p, nil
	}
	return dataplane.Plan{}, errors.New("Сервис не найден.")
}
