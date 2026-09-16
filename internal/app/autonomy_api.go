package app

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"slices"
	"sort"
	"time"

	"github.com/ArtixSx/razvilka/internal/autonomy"
	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/onboarding"
	"github.com/ArtixSx/razvilka/internal/providerfeed"
)

func autonomyDraftFingerprint(s config.ServiceState) string {
	data, _ := json.Marshal(s)
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

func autonomyDefinition(s catalog.Service) string {
	data, _ := json.Marshal(s)
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}
func (a *App) autonomyService(id string) (catalog.Service, bool) {
	for _, s := range a.catalogSnapshot().Services {
		if s.ID == id {
			return s, true
		}
	}
	return catalog.Service{}, false
}
func decodeAutonomyRequest(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 32<<10))
	dec.DisallowUnknownFields()
	if dec.Decode(v) != nil || dec.Decode(&struct{}{}) != io.EOF {
		writeJSON(w, 400, map[string]any{"error": "Некорректные параметры автономного режима."})
		return false
	}
	return true
}
func (a *App) autonomyAPI(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodGet && r.Method != http.MethodPut {
		methodNotAllowed(w)
		return
	}
	if a.loadAutonomy(r.Context()) != nil {
		writeJSON(w, 503, map[string]any{"error": "Настройки автоматики недоступны или требуют восстановления. Сеть не изменена."})
		return
	}
	if r.Method == http.MethodPut {
		var req struct {
			ExpectedRevision uint64          `json:"expected_revision"`
			Policy           autonomy.Policy `json:"policy"`
			Confirm          string          `json:"confirm"`
			ReleaseSafeMode  bool            `json:"release_safe_mode"`
			StarterSHA       string          `json:"starter_sha256,omitempty"`
			InitialServices  []string        `json:"initial_service_ids,omitempty"`
		}
		if !decodeAutonomyRequest(w, r, &req) {
			return
		}
		req.Policy.Schema = autonomy.Schema
		req.Policy.Revision = req.ExpectedRevision + 1
		if len(req.InitialServices) > 0 && req.StarterSHA == "" || req.ExpectedRevision == ^uint64(0) || req.Confirm != "SAVE_AUTONOMY" || autonomy.Validate(req.Policy) != nil {
			writeJSON(w, 400, map[string]any{"error": "Проверьте часовой пояс, источники, устройства и расписания."})
			return
		}
		known := map[string]bool{}
		for _, p := range providerfeed.Builtins() {
			known["feed-"+p.ID] = true
		}
		if a.Nodes != nil {
			snap, e := a.Nodes.Snapshot(r.Context(), time.Now())
			if e != nil {
				writeJSON(w, 503, map[string]any{"error": "Каталог подключений недоступен."})
				return
			}
			for _, s := range snap.Sources {
				known[s.ID] = true
			}
		}
		if a.NodeFeeds != nil {
			for _, s := range a.NodeFeeds.List() {
				known[s.SourceID] = true
			}
		}
		for _, id := range req.Policy.SourceIDs {
			if !known[id] {
				writeJSON(w, 400, map[string]any{"error": "Источник не известен локальному каталогу."})
				return
			}
		}
		a.autonomy.mu.Lock()
		if a.autonomy.doc.Policy.Revision != req.ExpectedRevision {
			a.autonomy.mu.Unlock()
			writeJSON(w, 409, map[string]any{"error": "Настройки изменились. Обновите страницу."})
			return
		}
		before := a.autonomy.doc.Policy
		oldServices, oldRuntime := a.autonomy.doc.Services, a.autonomy.doc.Runtime
		if req.StarterSHA != "" {
			services, runtime, e := onboarding.Enroll(a.catalogSnapshot(), starterConfigView(a.Store.Get()), before, req.Policy, oldServices, oldRuntime, req.StarterSHA, req.InitialServices)
			if e != nil {
				a.autonomy.mu.Unlock()
				writeJSON(w, 409, map[string]any{"code": "STARTER_REVIEW_CHANGED", "error": "Базовый набор или настройки изменились. Повторите просмотр мастера."})
				return
			}
			a.autonomy.doc.Services, a.autonomy.doc.Runtime = services, runtime
		}
		a.autonomy.doc.Policy = autonomy.Clone(req.Policy)
		err := a.persistAutonomyLocked(r.Context())
		if err != nil {
			a.autonomy.doc.Policy = before
			a.autonomy.doc.Services, a.autonomy.doc.Runtime = oldServices, oldRuntime
		}
		a.autonomy.mu.Unlock()
		if err != nil {
			writeJSON(w, 503, map[string]any{"error": "Разрешения не сохранены. Автоматика не запущена."})
			return
		}
		if req.ReleaseSafeMode && req.Policy.Enabled {
			// This is an explicit wizard consent, never an automatic bypass of Safe Mode.
			if a.Store.SetSafeMode(false) != nil {
				writeJSON(w, 409, map[string]any{"error": "Политика сохранена, но защитный режим остался включён."})
				return
			}
			mode := "auto"
			cfg := a.Store.Get()
			if a.Store.UpdateServiceControl(&mode, nil, cfg.Revision) != nil {
				writeJSON(w, 409, map[string]any{"error": "Политика сохранена; проверьте общий режим управления."})
				return
			}
		}
		a.wakeReconciler()
	}
	a.autonomy.mu.Lock()
	p := autonomy.Clone(a.autonomy.doc.Policy)
	services := map[string]autonomy.Service{}
	runtime := map[string]autonomy.Runtime{}
	for id, s := range a.autonomy.doc.Services {
		s.Sources = slices.Clone(s.Sources)
		services[id] = s
	}
	for id, s := range a.autonomy.doc.Runtime {
		runtime[id] = s.Clone()
	}
	maintenance := a.autonomy.maintenanceMessage
	blocked := a.autonomy.blocked
	a.autonomy.mu.Unlock()
	cfg := a.Store.Get()
	catalogServices := []map[string]any{}
	for _, service := range a.catalogSnapshot().Services {
		catalogServices = append(catalogServices, map[string]any{"id": service.ID, "name": service.Name, "custom": a.CustomServices != nil && a.CustomServices.Has(service.ID), "default_nfqws2": catalog.IsNFQWS2Starter(service)})
	}
	sort.Slice(catalogServices, func(i, j int) bool { return catalogServices[i]["name"].(string) < catalogServices[j]["name"].(string) })
	presets := []map[string]any{}
	for _, preset := range providerfeed.Builtins() {
		presets = append(presets, map[string]any{"id": "feed-" + preset.ID, "name": preset.Name, "interval_minutes": preset.DefaultRefreshIntervalMinutes})
	}
	writeJSON(w, 200, map[string]any{"policy": p, "starter": onboarding.Starter(a.catalogSnapshot(), starterConfigView(cfg), p, services), "services": services, "runtime": runtime, "blocked": blocked, "safe_mode": cfg.SafeMode, "manual": cfg.ServiceControl.EffectiveMode() == "manual", "stopped": cfg.ServiceControl.Stopped,
		"catalog_services": catalogServices, "source_presets": presets, "applied_services": cfg.AppliedServices, "server_time": time.Now().UTC(), "next_application_window": autonomy.NextWindow(p.Application, p.Timezone, time.Now()), "next_components_window": autonomy.NextWindow(p.Components, p.Timezone, time.Now()), "maintenance_message": maintenance,
		"capabilities": map[string]any{"automatic_initial_apply": true, "automatic_reserves": true, "scenario": "web", "source_timers": "saved-router-subscriptions", "automatic_install": false, "component_install": false, "note": "Тестовая реализация. Автоустановка программ закрыта до подписанных выпусков и аппаратно подтверждённого отката. Проверка и подготовка приложения по расписанию работают отдельно."}})
}

func (a *App) autonomyEnroll(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	var req struct {
		ServiceID        string   `json:"service_id"`
		Enabled          bool     `json:"enabled"`
		UseDefaults      bool     `json:"use_defaults"`
		AllLAN           bool     `json:"all_lan"`
		Sources          []string `json:"sources"`
		ExpectedRevision uint64   `json:"expected_revision"`
		Confirm          string   `json:"confirm"`
	}
	if !decodeAutonomyRequest(w, r, &req) {
		return
	}
	if a.loadAutonomy(r.Context()) != nil {
		writeJSON(w, 503, map[string]any{"error": "Хранилище автоматики недоступно."})
		return
	}
	p := a.autonomyPolicy()
	service, found := a.autonomyService(req.ServiceID)
	if req.Confirm != "MANAGE_SERVICE" || !found || !p.SetupComplete || p.Revision != req.ExpectedRevision {
		writeJSON(w, 409, map[string]any{"error": "Проверьте сервис и завершите мастер."})
		return
	}
	if req.UseDefaults {
		req.Sources = slices.Clone(p.DefaultSources)
		req.AllLAN = p.AllLAN
	}
	if autonomy.ValidateScope(req.AllLAN, req.Sources) != nil {
		writeJSON(w, 400, map[string]any{"error": "Явно выберите устройства или всю локальную сеть."})
		return
	}
	normalized, err := config.NormalizeSources(req.Sources)
	if err != nil {
		writeJSON(w, 400, map[string]any{"error": "Некорректные адреса устройств."})
		return
	}
	cfg := a.Store.Get()
	a.autonomy.mu.Lock()
	defer a.autonomy.mu.Unlock()
	if a.autonomy.doc.Policy.Revision != req.ExpectedRevision || a.autonomy.doc.Policy.Revision == ^uint64(0) {
		writeJSON(w, 409, map[string]any{"error": "Разрешения изменились."})
		return
	}
	if len(a.autonomy.doc.Services) >= autonomy.MaxServices {
		if _, ok := a.autonomy.doc.Services[req.ServiceID]; !ok {
			writeJSON(w, 409, map[string]any{"error": "Лимит управляемых сервисов достигнут."})
			return
		}
	}
	s := autonomy.Service{ID: req.ServiceID, Enabled: req.Enabled, AllLAN: req.AllLAN, Sources: normalized, Definition: autonomyDefinition(service), DraftFingerprint: autonomyDraftFingerprint(cfg.Services[req.ServiceID]), ExpectedRoute: selectedRoute(cfg.Services[req.ServiceID])}
	// Enrollment does not apply an unrelated draft, nor change any live route.
	a.autonomy.doc.Services[req.ServiceID] = s
	a.autonomy.doc.Runtime[req.ServiceID] = autonomy.Runtime{State: "pending", Message: "В очереди проверки. Маршрут пока не менялся.", Reserves: []string{}, Switches: []time.Time{}}
	a.autonomy.doc.Policy.Revision++
	if err = a.persistAutonomyLocked(r.Context()); err != nil {
		writeJSON(w, 503, map[string]any{"error": "Сохранение не подтверждено. Автоматика заблокирована."})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "live_applied": false, "revision": a.autonomy.doc.Policy.Revision, "service": s})
}

// Only persisted, explicitly selected presets are installed as subscriptions.
// Removing a source from consent stops new use; existing saved subscriptions
// remain independently managed on the Sources page.
func (a *App) autonomyEnsureFeeds(ctx context.Context, p autonomy.Policy) error {
	if a.NodeFeeds == nil || !a.NodeFeeds.Persistent() {
		return nil
	}
	existing := map[string]bool{}
	for _, s := range a.NodeFeeds.List() {
		existing[s.SourceID] = true
	}
	for _, preset := range providerfeed.Builtins() {
		id := "feed-" + preset.ID
		if !slices.Contains(p.SourceIDs, id) || existing[id] {
			continue
		}
		_, e := a.NodeFeeds.Save(ctx, "", providerfeed.SaveRequest{Request: providerfeed.Request{PresetID: preset.ID, Limit: 32, AcceptPartial: true}, Name: preset.Name, Enabled: true, RefreshIntervalMinutes: preset.DefaultRefreshIntervalMinutes})
		if e != nil {
			return e
		}
	}
	return nil
}
