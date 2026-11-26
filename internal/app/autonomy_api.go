package app

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
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
			ExpectedRevision uint64 `json:"expected_revision"`
			Policy           struct {
				autonomy.Policy
				AllLAN                 json.RawMessage `json:"all_lan"`
				DefaultSources         json.RawMessage `json:"default_sources"`
				MissingComponentChoice json.RawMessage `json:"install_missing_components"`
				FailureThreshold       json.RawMessage `json:"public_node_failure_threshold"`
				WARPRegistration       json.RawMessage `json:"allow_initial_warp_registration"`
				MASQUERegistration     *bool           `json:"allow_initial_masque_registration"`
			} `json:"policy"`
			Confirm         string    `json:"confirm"`
			ReleaseSafeMode bool      `json:"release_safe_mode"`
			UseNetworkScope bool      `json:"use_network_scope"`
			StarterSHA      string    `json:"starter_sha256,omitempty"`
			StarterIDs      *[]string `json:"starter_service_ids,omitempty"`
			InitialServices []string  `json:"initial_service_ids,omitempty"`
		}
		if !decodeAutonomyRequest(w, r, &req) {
			return
		}
		policy := req.Policy.Policy
		if req.UseNetworkScope {
			if req.Policy.AllLAN != nil || req.Policy.DefaultSources != nil || !policy.SetupComplete || req.StarterSHA != "" && req.StarterIDs == nil {
				writeJSON(w, 400, map[string]any{"error": "Первый запуск принимает выбранные сервисы и сохраняет действующую область сети."})
				return
			}
		} else if req.Policy.AllLAN != nil && json.Unmarshal(req.Policy.AllLAN, &policy.AllLAN) != nil ||
			req.Policy.DefaultSources != nil && json.Unmarshal(req.Policy.DefaultSources, &policy.DefaultSources) != nil {
			writeJSON(w, 400, map[string]any{"error": "Некорректная область устройств."})
			return
		}
		warpSelected := slices.Contains(policy.PreferredRoutes, "warp-wg")
		var warpRegistration *bool
		if req.Policy.WARPRegistration != nil {
			if json.Unmarshal(req.Policy.WARPRegistration, &warpRegistration) != nil || warpRegistration == nil {
				writeJSON(w, 400, map[string]any{"error": "Некорректное разрешение на первичную регистрацию WARP WireGuard."})
				return
			}
			if *warpRegistration && !warpSelected {
				writeJSON(w, 400, map[string]any{"error": "Согласие на первичную регистрацию WARP WireGuard требует выбора этого способа."})
				return
			}
		}
		policy.AllowInitialWARPRegistration = warpRegistration
		masqueSelected := slices.Contains(policy.PreferredRoutes, "usque")
		if req.Policy.MASQUERegistration != nil && *req.Policy.MASQUERegistration && !masqueSelected {
			writeJSON(w, 400, map[string]any{"error": "Согласие на первичную регистрацию MASQUE требует выбора способа USQUE."})
			return
		}
		choice := req.Policy.MissingComponentChoice
		if choice != nil && json.Unmarshal(choice, &policy.InstallMissingComponents) != nil {
			writeJSON(w, 400, map[string]any{"error": "Некорректное разрешение на установку компонентов."})
			return
		}
		threshold := req.Policy.FailureThreshold
		if threshold != nil && json.Unmarshal(threshold, &policy.PublicNodeFailureThreshold) != nil {
			writeJSON(w, 400, map[string]any{"error": "Некорректный порог отказов публичного узла."})
			return
		}
		policy.Schema = autonomy.Schema
		policy.Revision = req.ExpectedRevision + 1
		if (len(req.InitialServices) > 0 || req.StarterIDs != nil) && req.StarterSHA == "" || req.ExpectedRevision == ^uint64(0) || req.Confirm != "SAVE_AUTONOMY" {
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
			// Manual imports have a fixed source ID even before the first profile is added.
			known["manual"] = true
			for _, s := range snap.Sources {
				known[s.ID] = true
			}
		}
		if a.NodeFeeds != nil {
			for _, s := range a.NodeFeeds.List() {
				known[s.SourceID] = true
			}
		}
		for _, id := range policy.SourceIDs {
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
		cfg := a.Store.Get()
		policy.ManagedLANOnly = before.ManagedLANOnly
		if req.UseNetworkScope {
			if before.SetupComplete {
				a.autonomy.mu.Unlock()
				writeJSON(w, 409, map[string]any{"error": "Первоначальная настройка уже сохранена."})
				return
			}
			policy.AllLAN, policy.DefaultSources, policy.ManagedLANOnly = initialAutonomyScope(cfg, before, a.autonomy.image.Exists)
		} else if !before.SetupComplete && policy.SetupComplete && policy.AllLAN && req.StarterSHA != "" {
			// An already open first wizard may still send the old scope fields.
			policy.ManagedLANOnly = true
		}
		keepEmpty := !before.AllLAN && len(before.DefaultSources) == 0 && before.SetupComplete
		validate := autonomy.Validate
		if req.UseNetworkScope || keepEmpty {
			validate = autonomy.ValidateStored
		}
		if validate(policy) != nil {
			a.autonomy.mu.Unlock()
			writeJSON(w, 400, map[string]any{"error": "Проверьте часовой пояс, источники, устройства и расписания."})
			return
		}
		// Older clients omit this field. Only an explicit null may restore the
		// legacy window-bound behavior after an explicit choice was saved.
		if choice == nil {
			policy.InstallMissingComponents = before.InstallMissingComponents
		}
		// Older clients omit this threshold. Explicit zero or null resets it.
		if threshold == nil {
			policy.PublicNodeFailureThreshold = before.PublicNodeFailureThreshold
		}
		// Omission by an older client preserves a saved choice. Removing the
		// method explicitly revokes even the old health-policy fallback.
		if req.Policy.WARPRegistration == nil {
			policy.AllowInitialWARPRegistration = before.AllowInitialWARPRegistration
			if !warpSelected && slices.Contains(before.PreferredRoutes, "warp-wg") {
				denied := false
				policy.AllowInitialWARPRegistration = &denied
			}
		}
		policy.AllowInitialMASQUERegistration = masqueSelected && before.AllowInitialMASQUERegistration
		if req.Policy.MASQUERegistration != nil {
			policy.AllowInitialMASQUERegistration = *req.Policy.MASQUERegistration
		}
		oldServices, oldRuntime := a.autonomy.doc.Services, a.autonomy.doc.Runtime
		installGranted := policy.InstallMissingComponents != nil && *policy.InstallMissingComponents &&
			(before.InstallMissingComponents == nil || !*before.InstallMissingComponents)
		if req.StarterSHA != "" {
			catalog, current := a.catalogSnapshot(), starterConfigView(cfg)
			var services map[string]autonomy.Service
			var runtime map[string]autonomy.Runtime
			var e error
			if req.UseNetworkScope {
				services, runtime, e = onboarding.EnrollForAuto(catalog, current, before, policy, oldServices, oldRuntime, req.StarterSHA, req.InitialServices, *req.StarterIDs)
			} else {
				services, runtime, e = onboarding.EnrollSelected(catalog, current, before, policy, oldServices, oldRuntime, req.StarterSHA, req.InitialServices, req.StarterIDs)
			}
			if e != nil {
				a.autonomy.mu.Unlock()
				writeJSON(w, 409, map[string]any{"code": "STARTER_REVIEW_CHANGED", "error": "Базовый набор или настройки изменились. Повторите просмотр мастера."})
				return
			}
			a.autonomy.doc.Services, a.autonomy.doc.Runtime = services, runtime
		}
		masqueGranted := policy.AllowInitialMASQUERegistration && !before.AllowInitialMASQUERegistration
		warpGranted := policy.AllowInitialWARPRegistration != nil && *policy.AllowInitialWARPRegistration &&
			(before.AllowInitialWARPRegistration == nil || !*before.AllowInitialWARPRegistration)
		// The new policy owns the status of checks it interrupted. An older
		// worker can no longer report how to continue under this revision.
		// Also wake services whose prior component wait lasted until a window.
		runtime := maps.Clone(a.autonomy.doc.Runtime)
		requeued := false
		for id, entry := range runtime {
			service := a.autonomy.doc.Services[id]
			if !service.Enabled || service.Removing {
				continue
			}
			switch {
			case entry.State == homeServiceCheckedState:
				withdrawHomeReserve(&entry)
				entry.Message = "Настройки изменились. Резерв будет проверен повторно."
			case entry.State == "checking":
				entry.Message = "Настройки изменились. Сервис в очереди проверки."
			case installGranted && autonomyWaitingForComponent(entry):
				entry.Message = "Разрешение на установку сохранено. Сервис в очереди проверки."
			case masqueGranted && entry.State == "masque-consent-required":
				entry.Message = "Согласие на подготовку MASQUE сохранено. Сервис в очереди проверки."
			case warpGranted && entry.State == "warp-consent-required":
				entry.Message = "Согласие на подготовку WARP WireGuard сохранено. Сервис в очереди проверки."
			default:
				continue
			}
			entry.State = "pending"
			entry.NextCheck = time.Time{}
			runtime[id] = entry
			requeued = true
		}
		a.autonomy.doc.Runtime = runtime
		a.autonomy.doc.Policy = autonomy.Clone(policy)
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
		a.cancelNodeReadiness()
		if req.ReleaseSafeMode && policy.Enabled && (!req.UseNetworkScope || !cfg.ServiceControl.Stopped) {
			// This is an explicit wizard consent, never an automatic bypass of Safe Mode.
			if err := a.clearRetiredSafeMode(); err != nil {
				a.writeOperationFailure(w, err)
				return
			}
			mode := "auto"
			cfg := a.Store.Get()
			if cfg.ServiceControl.EffectiveMode() != "auto" && a.updateServiceControlMode(r.Context(), &mode, nil, cfg.Revision) != nil {
				writeJSON(w, 409, map[string]any{"error": "Политика сохранена; проверьте общий режим управления."})
				return
			}
		}
		a.wakeReconciler()
		if (requeued || installGranted || masqueGranted || warpGranted) && policy.Enabled {
			a.wakeAutonomy()
		}
	}
	writeJSON(w, 200, a.autonomyView(time.Now()))
}

// Called only by an admitted readback or the background presentation collector.
// HTTP panel polling must never call this file-backed collector directly.
func (a *App) autonomyView(now time.Time) map[string]any {
	a.autonomy.mu.Lock()
	p := autonomy.Clone(a.autonomy.doc.Policy)
	saved := a.autonomy.image.Exists
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
	refill := a.autonomy.refillState
	blocked := a.autonomy.blocked
	a.autonomy.mu.Unlock()
	a.reconciler.mu.Lock()
	schedulerBlocked, schedulerCode := a.reconciler.blocked, a.reconciler.blockedCode
	a.reconciler.mu.Unlock()
	blockedCode := ""
	if schedulerBlocked {
		blocked = true
		blockedCode = schedulerCode
		maintenance = "Автопилот приостановлен: планировщик не подтвердил сохранение очереди. Требуется проверка диагностики; текущие подключения не отключены."
	}
	cfg := a.Store.Get()
	networkScope := ""
	for id, entry := range runtime {
		if entry.State == homeServiceCheckedState && (entry.ReserveConfigRevision != cfg.Revision || !now.Before(entry.ReserveValidUntil) || now.Before(entry.ReserveCheckedAt)) {
			runtime[id] = pendingHomeReserve(entry)
		}
	}
	if cfg.NetworkPolicy != nil {
		networkScope = cfg.NetworkPolicy.Clients.Mode
	} else if cfg.AppliedNetworkPolicy != nil {
		networkScope = cfg.AppliedNetworkPolicy.Clients.Mode
	}
	initialScope := ""
	if !p.SetupComplete {
		all, sources, _ := initialAutonomyScope(cfg, p, saved)
		switch {
		case !all && len(sources) == 0:
			initialScope = "empty"
		case !all || networkScope == "selected_devices":
			initialScope = "selected"
		case networkScope != "":
			initialScope = "existing"
		default:
			initialScope = "all"
		}
	}
	definitions := a.catalogSnapshot()
	catalogServices := []map[string]any{}
	for _, service := range definitions.Services {
		entry := map[string]any{"id": service.ID, "name": service.Name, "custom": a.CustomServices != nil && a.CustomServices.Has(service.ID), "default_nfqws2": catalog.IsNFQWS2Starter(service)}
		if enrolled, ok := services[service.ID]; ok && !enrolled.Removing {
			if current := autonomyDefinition(service); current != enrolled.Definition {
				entry["review_definition"] = current
			}
		}
		catalogServices = append(catalogServices, entry)
	}
	sort.Slice(catalogServices, func(i, j int) bool { return catalogServices[i]["name"].(string) < catalogServices[j]["name"].(string) })
	presets := []map[string]any{}
	choiceNames := map[string]string{"manual": "Добавленные вручную"}
	for _, preset := range providerfeed.Builtins() {
		presets = append(presets, map[string]any{"id": "feed-" + preset.ID, "name": preset.Name, "interval_minutes": preset.DefaultRefreshIntervalMinutes})
		choiceNames["feed-"+preset.ID] = preset.Name
	}
	choices := []map[string]any{}
	for index, id := range p.SourceIDs {
		name, known := choiceNames[id]
		kind := "unknown"
		if !known {
			name = fmt.Sprintf("Источник %d", index+1)
		} else if id == "manual" {
			kind = "manual"
		} else {
			kind = "community"
		}
		choices = append(choices, map[string]any{"id": id, "name": name, "kind": kind})
	}
	// Expose only bounded scheduling/readback metadata to the authenticated UI.
	// Never expose old raw refresh errors, destinations or full plan objects here.
	var addressRefresh map[string]any
	if a.Dataplane != nil {
		if v, err := a.Dataplane.CommittedPolicyRefresh(); err == nil && v != nil {
			addressRefresh = map[string]any{"state": v.State, "checked_at": v.CheckedAt}
		}
	}
	warpRegistrationAllowed := false
	if p.AllowInitialWARPRegistration != nil {
		warpRegistrationAllowed = *p.AllowInitialWARPRegistration && slices.Contains(p.PreferredRoutes, "warp-wg")
	} else if a.Warp != nil {
		warpRegistrationAllowed = autonomyWARPRegistrationAllowed(p, a.Warp.Health().Policy)
	}
	return map[string]any{"policy": p, "starter": onboarding.Starter(definitions, starterConfigView(cfg), p, services), "services": services, "runtime": runtime, "blocked": blocked, "blocked_code": blockedCode, "safe_mode": cfg.SafeMode, "manual": cfg.ServiceControl.EffectiveMode() == "manual", "stopped": cfg.ServiceControl.Stopped,
		"catalog_services": catalogServices, "source_presets": presets, "source_choices": choices, "applied_services": cfg.AppliedServices, "server_time": now.UTC(), "next_application_window": autonomy.NextWindow(p.Application, p.Timezone, now), "next_components_window": autonomy.NextWindow(p.Components, p.Timezone, now), "maintenance_message": maintenance, "reserve_refill": refill, "address_refresh": addressRefresh, "node_readiness": a.nodeReadinessSnapshot(now),
		"network_scope_mode": networkScope, "initial_scope_mode": initialScope, "warp_initial_registration_allowed": warpRegistrationAllowed, "capabilities": a.autonomyCapabilities(p, cfg, blocked, blockedCode)}
}

func (a *App) autonomyEnroll(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		service, found := a.autonomyService(r.URL.Query().Get("review"))
		if !found {
			writeJSON(w, 404, map[string]any{"error": "Сервис отсутствует в каталоге."})
			return
		}
		if a.loadAutonomy(r.Context()) != nil {
			writeJSON(w, 503, map[string]any{"error": "Хранилище автоматики недоступно."})
			return
		}
		digest := autonomyDefinition(service)
		a.autonomy.mu.Lock()
		enrolled, ok := a.autonomy.doc.Services[service.ID]
		revision := a.autonomy.doc.Policy.Revision
		a.autonomy.mu.Unlock()
		if !ok || enrolled.Removing || digest == enrolled.Definition {
			writeJSON(w, 409, map[string]any{"error": "Список сервисов изменился. Обновите панель."})
			return
		}
		writeJSON(w, 200, map[string]any{"service_id": service.ID, "expected_revision": revision, "expected_definition": digest, "domains": service.Domains, "cidrs": service.CIDRs, "probe_url": service.ProbeURL, "probes": service.Probes, "strategy": service.Strategy, "source_refs": service.SourceRefs})
		return
	}
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	var req struct {
		ServiceID          string   `json:"service_id"`
		Enabled            bool     `json:"enabled"`
		UseDefaults        bool     `json:"use_defaults"`
		AllLAN             bool     `json:"all_lan"`
		Sources            []string `json:"sources"`
		ExpectedRevision   uint64   `json:"expected_revision"`
		ExpectedDefinition string   `json:"expected_definition"`
		Confirm            string   `json:"confirm"`
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
	review := req.Confirm == "REVIEW_SERVICE_DEFINITION"
	if (!review && req.Confirm != "MANAGE_SERVICE") || !found || !p.SetupComplete || p.Revision != req.ExpectedRevision {
		writeJSON(w, 409, map[string]any{"error": "Проверьте сервис и завершите мастер."})
		return
	}
	if req.UseDefaults {
		req.Sources = slices.Clone(p.DefaultSources)
		req.AllLAN = p.AllLAN
	}
	normalized, err := config.NormalizeSources(req.Sources)
	if err != nil {
		writeJSON(w, 400, map[string]any{"error": "Некорректные адреса устройств."})
		return
	}
	cfg := a.Store.Get()
	a.autonomy.mu.Lock()
	permissionsSaved := false
	defer func() {
		a.autonomy.mu.Unlock()
		if permissionsSaved {
			a.cancelNodeReadiness()
			a.wakeAutonomy()
		}
	}()
	if a.autonomy.doc.Policy.Revision != req.ExpectedRevision || a.autonomy.doc.Policy.Revision == ^uint64(0) {
		writeJSON(w, 409, map[string]any{"error": "Разрешения изменились."})
		return
	}
	oldService, enrolled := a.autonomy.doc.Services[req.ServiceID]
	retainEmpty := !req.AllLAN && len(req.Sources) == 0 &&
		(req.UseDefaults || enrolled && !oldService.AllLAN && len(oldService.Sources) == 0)
	if !review && !retainEmpty && autonomy.ValidateScope(req.AllLAN, req.Sources) != nil {
		writeJSON(w, 400, map[string]any{"error": "Явно выберите устройства или всю локальную сеть."})
		return
	}
	definition := autonomyDefinition(service)
	changed := enrolled && oldService.Definition != definition
	if review && (!changed || oldService.Removing || req.ExpectedDefinition != definition) || !review && changed && req.Enabled {
		writeJSON(w, 409, map[string]any{"error": "Откройте актуальный состав сервиса и подтвердите его."})
		return
	}
	if !enrolled && len(a.autonomy.doc.Services) >= autonomy.MaxServices {
		writeJSON(w, 409, map[string]any{"error": "Лимит управляемых сервисов достигнут."})
		return
	}
	oldRuntime, hadRuntime := a.autonomy.doc.Runtime[req.ServiceID]
	draft := cfg.Services[req.ServiceID]
	fingerprint := autonomyDraftFingerprint(draft)
	expectedRoute := selectedRoute(draft)
	if enrolled && !oldService.Removing && oldService.DraftFingerprint == fingerprint {
		expectedRoute = oldService.ExpectedRoute
	}
	s := autonomy.Service{ID: req.ServiceID, Enabled: req.Enabled, AllLAN: req.AllLAN,
		ManagedLANOnly: req.AllLAN && (p.ManagedLANOnly || oldService.ManagedLANOnly), Sources: normalized,
		Definition: definition, DraftFingerprint: fingerprint, ExpectedRoute: expectedRoute}
	if review {
		s = oldService
		s.Definition = definition
	} else if changed && !req.Enabled {
		// Pausing a service does not approve a catalog edit or a new draft.
		s = oldService
		s.Enabled = false
	}
	// Enrollment does not apply an unrelated draft, nor change any live route.
	a.autonomy.doc.Services[req.ServiceID] = s
	a.autonomy.doc.Runtime[req.ServiceID] = autonomy.Runtime{State: "pending", Message: "В очереди проверки. Маршрут пока не менялся.", Reserves: []string{}, Switches: slices.Clone(oldRuntime.Switches)}
	a.autonomy.doc.Policy.Revision++
	if err = a.persistAutonomyLocked(r.Context()); err != nil {
		a.autonomy.doc.Policy.Revision = req.ExpectedRevision
		if enrolled {
			a.autonomy.doc.Services[req.ServiceID] = oldService
		} else {
			delete(a.autonomy.doc.Services, req.ServiceID)
		}
		if hadRuntime {
			a.autonomy.doc.Runtime[req.ServiceID] = oldRuntime
		} else {
			delete(a.autonomy.doc.Runtime, req.ServiceID)
		}
		writeJSON(w, 503, map[string]any{"error": "Сохранение не подтверждено. Автоматика заблокирована."})
		return
	}
	permissionsSaved = true
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
	var errs []error
	for _, preset := range providerfeed.Builtins(p.PreferredSourceIDs...) {
		id := "feed-" + preset.ID
		if !slices.Contains(p.SourceIDs, id) || existing[id] {
			continue
		}
		if err := ctx.Err(); err != nil {
			errs = append(errs, err)
			break
		}
		_, e := a.NodeFeeds.Save(ctx, "", providerfeed.SaveRequest{Request: providerfeed.Request{PresetID: preset.ID, Limit: 32, AcceptPartial: true}, Name: preset.Name, Enabled: true, RefreshIntervalMinutes: preset.DefaultRefreshIntervalMinutes})
		if e != nil {
			errs = append(errs, fmt.Errorf("save preset %s: %w", id, e))
		}
	}
	return errors.Join(errs...)
}
