package app

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/engine"
	"github.com/ArtixSx/razvilka/internal/engineconfig"
	routecatalog "github.com/ArtixSx/razvilka/internal/routes"
	"github.com/ArtixSx/razvilka/internal/sources"
	"github.com/ArtixSx/razvilka/internal/systemprobe"
	"github.com/ArtixSx/razvilka/internal/telemetry"
	"github.com/ArtixSx/razvilka/internal/testlab"
)

const Version = "0.0.7-control-lab"

type App struct {
	Store           *config.Store
	Catalog         catalog.Catalog
	Sources         *sources.Manager
	Telemetry       *telemetry.Store
	EngineConfigs   *engineconfig.Manager
	TestLab         *testlab.Runner
	Start           time.Time
	EffectiveListen string
}

type serviceView struct {
	catalog.Service
	Enabled      bool   `json:"enabled"`
	Mode         string `json:"mode"`
	Route        string `json:"route"`
	Planned      string `json:"planned_engine"`
	Applied      bool   `json:"applied_enabled"`
	AppliedRoute string `json:"applied_route"`
	Dirty        bool   `json:"dirty"`
}

func (a *App) Handler(static http.Handler) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/status", a.status)
	mux.HandleFunc("/api/v1/engines", a.engines)
	mux.HandleFunc("/api/v1/engine-configs", a.engineConfigs)
	mux.HandleFunc("/api/v1/engine-configs/", a.engineConfigAction)
	mux.HandleFunc("/api/v1/testlab", a.testLabSnapshot)
	mux.HandleFunc("/api/v1/testlab/current", a.testLabCurrent)
	mux.HandleFunc("/api/v1/routes/options", a.routeOptions)
	mux.HandleFunc("/api/v1/services", a.services)
	mux.HandleFunc("/api/v1/services/", a.service)
	mux.HandleFunc("/api/v1/plan", a.plan)
	mux.HandleFunc("/api/v1/apply", a.apply)
	mux.HandleFunc("/api/v1/discard", a.discard)
	mux.HandleFunc("/api/v1/system", a.systemInfo)
	mux.HandleFunc("/api/v1/config/export", a.configExport)
	mux.HandleFunc("/api/v1/connections", a.connections)
	mux.HandleFunc("/api/v1/connections/stream", a.connectionStream)
	mux.HandleFunc("/api/v1/sources", a.sourceList)
	mux.HandleFunc("/api/v1/sources/refresh", a.sourceRefreshAll)
	mux.HandleFunc("/api/v1/sources/", a.sourceAction)
	mux.Handle("/", static)
	return securityHeaders(mux)
}

func (a *App) status(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	cfg := a.Store.Get()
	enabled := 0
	for _, st := range cfg.Services {
		if st.Enabled {
			enabled++
		}
	}
	engines := engine.Detector{}.All()
	running, installed := 0, 0
	for _, e := range engines {
		if e.Installed {
			installed++
		}
		if e.Running {
			running++
		}
	}
	readySources, sourceCount := 0, 0
	if a.Sources != nil {
		ss := a.Sources.List()
		sourceCount = len(ss)
		for _, s := range ss {
			if s.Ready {
				readySources++
			}
		}
	}
	activeConnections := 0
	if a.Telemetry != nil {
		activeConnections, _ = a.Telemetry.Counts()
	}
	configDrafts := 0
	if a.EngineConfigs != nil {
		for _, ev := range a.EngineConfigs.List() {
			for _, fv := range ev.Files {
				if fv.Staged {
					configDrafts++
				}
			}
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"name": "RAZVILKA", "version": Version, "safe_mode": cfg.SafeMode,
		"uptime_seconds": int(time.Since(a.Start).Seconds()), "listen": effectiveListen(a.EffectiveListen, cfg.Listen),
		"enabled_services": enabled, "catalog_services": len(a.Catalog.Services),
		"engines_installed": installed, "engines_running": running,
		"sources_ready": readySources, "sources_total": sourceCount,
		"active_connections": activeConnections, "engine_config_drafts": configDrafts,
		"pending_changes": a.Store.Dirty(), "revision": cfg.Revision, "applied_revision": cfg.AppliedRevision, "last_applied_at": cfg.LastAppliedAt,
	})
}

func (a *App) engines(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	writeJSON(w, http.StatusOK, engine.Detector{}.All())
}

func (a *App) engineConfigs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	if a.EngineConfigs == nil {
		http.Error(w, "engine config manager disabled", http.StatusServiceUnavailable)
		return
	}
	writeJSON(w, http.StatusOK, a.EngineConfigs.List())
}

func (a *App) engineConfigAction(w http.ResponseWriter, r *http.Request) {
	if a.EngineConfigs == nil {
		http.Error(w, "engine config manager disabled", http.StatusServiceUnavailable)
		return
	}
	path := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/v1/engine-configs/"), "/")
	engineID, action, ok := strings.Cut(path, "/")
	if !ok || engineID == "" || action == "" {
		http.NotFound(w, r)
		return
	}
	fileID := r.URL.Query().Get("file")
	if fileID == "" {
		fileID = "main"
	}
	switch action {
	case "file":
		switch r.Method {
		case http.MethodGet:
			content, err := a.EngineConfigs.Read(engineID, fileID)
			if err != nil {
				http.Error(w, err.Error(), http.StatusNotFound)
				return
			}
			writeJSON(w, http.StatusOK, content)
		case http.MethodPut:
			var in struct {
				Content string `json:"content"`
			}
			if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 2<<20)).Decode(&in); err != nil {
				http.Error(w, "invalid json", http.StatusBadRequest)
				return
			}
			content, err := a.EngineConfigs.Stage(engineID, fileID, in.Content)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			writeJSON(w, http.StatusOK, content)
		default:
			methodNotAllowed(w)
		}
	case "validate":
		if r.Method != http.MethodPost {
			methodNotAllowed(w)
			return
		}
		v := a.EngineConfigs.Validate(engineID, fileID)
		writeJSON(w, http.StatusOK, v)
	case "discard":
		if r.Method != http.MethodPost {
			methodNotAllowed(w)
			return
		}
		if err := a.EngineConfigs.Discard(engineID, fileID); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "engine_id": engineID, "file_id": fileID})
	case "apply":
		if r.Method != http.MethodPost {
			methodNotAllowed(w)
			return
		}
		dst, err := a.EngineConfigs.Apply(engineID, fileID, a.Store.Get().SafeMode)
		if err != nil {
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "path": dst})
	default:
		http.NotFound(w, r)
	}
}

func (a *App) testLabSnapshot(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	if a.TestLab == nil {
		http.Error(w, "test lab disabled", http.StatusServiceUnavailable)
		return
	}
	writeJSON(w, http.StatusOK, a.TestLab.Snapshot(a.Catalog))
}

func (a *App) testLabCurrent(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	if a.TestLab == nil {
		http.Error(w, "test lab disabled", http.StatusServiceUnavailable)
		return
	}
	ids, err := testlab.DecodeRunRequest(r.Body)
	if err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	results := a.TestLab.ProbeCurrent(ctx, a.Catalog, ids)
	writeJSON(w, http.StatusOK, map[string]any{
		"mode": "current-routing", "safe_mode": a.Store.Get().SafeMode, "results": results,
		"note": "This probe measures the routing currently applied on the router. Route-by-route sweep will be enabled only after isolated engine adapters are available.",
	})
}

func (a *App) routeOptions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	writeJSON(w, http.StatusOK, routecatalog.Options())
}

func (a *App) services(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	cfg := a.Store.Get()
	views := make([]serviceView, 0, len(a.Catalog.Services))
	for _, s := range a.Catalog.Services {
		st := cfg.Services[s.ID]
		applied := cfg.AppliedServices[s.ID]
		selected := selectedRoute(st)
		planned := selected
		if selected == "auto" {
			planned = plannedEngine(s, cfg.EngineOrder)
		}
		appliedRoute := selectedRoute(applied)
		dirty := st.Enabled != applied.Enabled || selected != appliedRoute
		views = append(views, serviceView{Service: s, Enabled: st.Enabled, Mode: selected, Route: selected, Planned: planned, Applied: applied.Enabled, AppliedRoute: appliedRoute, Dirty: dirty})
	}
	sort.Slice(views, func(i, j int) bool {
		if views[i].Category == views[j].Category {
			return views[i].Name < views[j].Name
		}
		return views[i].Category < views[j].Category
	})
	writeJSON(w, http.StatusOK, views)
}

func (a *App) service(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		methodNotAllowed(w)
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/api/v1/services/")
	if id == "" || !a.hasService(id) {
		http.Error(w, "unknown service", http.StatusNotFound)
		return
	}
	var in config.ServiceState
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 32<<10)).Decode(&in); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	selected := in.Route
	if selected == "" {
		selected = in.Mode
	}
	if selected == "" {
		selected = "auto"
	}
	if !routecatalog.Valid(selected) {
		http.Error(w, "invalid route", http.StatusBadRequest)
		return
	}
	in.Route = selected
	in.Mode = selected
	if err := a.Store.UpdateService(id, in); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "id": id, "state": in})
}

func selectedRoute(st config.ServiceState) string {
	if st.Route != "" {
		return st.Route
	}
	if st.Mode != "" {
		return st.Mode
	}
	return "auto"
}

func effectiveListen(actual, configured string) string {
	if actual != "" {
		return actual
	}
	return configured
}

func (a *App) plan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	cfg := a.Store.Get()
	var rows []map[string]any
	for _, s := range a.Catalog.Services {
		st := cfg.Services[s.ID]
		if !st.Enabled {
			continue
		}
		selected := selectedRoute(st)
		resolved := selected
		if selected == "auto" {
			resolved = plannedEngine(s, cfg.EngineOrder)
		}
		rows = append(rows, map[string]any{
			"service": s.Name, "id": s.ID, "selected_route": selected, "engine": resolved,
			"domains": len(s.Domains), "cidrs": len(s.CIDRs), "source_refs": s.SourceRefs,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"safe_mode": cfg.SafeMode,
		"note":      "v0.0.7-control-lab: target UI, staged Apply and telemetry model are enabled; dataplane adapters still do not change firewall/routing/DNS in Safe Mode.",
		"routes":    rows,
	})
}

func (a *App) apply(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	// Safe Lab: commit desired state only. Dataplane transactions will be inserted before this commit.
	if err := a.Store.ApplyDraft(); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "safe_mode": a.Store.Get().SafeMode, "pending_changes": false, "note": "Draft committed. Safe Mode still prevents firewall/DNS/route changes."})
}

func (a *App) discard(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	if err := a.Store.DiscardDraft(); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "pending_changes": false})
}

func (a *App) systemInfo(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	writeJSON(w, http.StatusOK, systemprobe.Probe())
}

func (a *App) configExport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	cfg := a.Store.Get()
	writeJSON(w, http.StatusOK, map[string]any{"schema": 1, "version": Version, "config": cfg, "catalog_services": len(a.Catalog.Services)})
}

func (a *App) connections(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	includeClosed, _ := strconv.ParseBool(r.URL.Query().Get("include_closed"))
	if a.Telemetry == nil {
		writeJSON(w, http.StatusOK, map[string]any{"connections": []any{}, "live": false, "reason": "telemetry store disabled"})
		return
	}
	active, closed := a.Telemetry.Counts()
	writeJSON(w, http.StatusOK, map[string]any{
		"connections": a.Telemetry.Snapshot(includeClosed), "live": true,
		"active": active, "closed": closed,
		"note": "Connections appear only when a dataplane adapter publishes real route evidence; RAZVILKA never invents live rows.",
	})
}

func (a *App) connectionStream(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	if a.Telemetry == nil {
		http.Error(w, "telemetry disabled", http.StatusServiceUnavailable)
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	ch, cancel := a.Telemetry.Subscribe()
	defer cancel()
	send := func() bool {
		payload, err := json.Marshal(a.Telemetry.Snapshot(false))
		if err != nil {
			return false
		}
		if _, err = fmt.Fprintf(w, "event: connections\ndata: %s\n\n", payload); err != nil {
			return false
		}
		flusher.Flush()
		return true
	}
	if !send() {
		return
	}
	heartbeat := time.NewTicker(20 * time.Second)
	defer heartbeat.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case _, ok := <-ch:
			if !ok || !send() {
				return
			}
		case <-heartbeat.C:
			if _, err := fmt.Fprint(w, ": keepalive\n\n"); err != nil {
				return
			}
			flusher.Flush()
		}
	}
}

func (a *App) sourceList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	if a.Sources == nil {
		writeJSON(w, http.StatusOK, []any{})
		return
	}
	writeJSON(w, http.StatusOK, a.Sources.List())
}

func (a *App) sourceRefreshAll(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	if a.Sources == nil {
		http.Error(w, "sources disabled", http.StatusServiceUnavailable)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 90*time.Second)
	defer cancel()
	writeJSON(w, http.StatusOK, a.Sources.RefreshEnabled(ctx))
}

func (a *App) sourceAction(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	if a.Sources == nil {
		http.Error(w, "sources disabled", http.StatusServiceUnavailable)
		return
	}
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/sources/")
	id, action, ok := strings.Cut(path, "/")
	if !ok || id == "" || action != "refresh" {
		http.NotFound(w, r)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 45*time.Second)
	defer cancel()
	if err := a.Sources.Refresh(ctx, id); err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	for _, s := range a.Sources.List() {
		if s.ID == id {
			writeJSON(w, http.StatusOK, s)
			return
		}
	}
	http.Error(w, "unknown source", http.StatusNotFound)
}

func plannedEngine(s catalog.Service, order []string) string {
	if len(s.Strategy) > 0 {
		return s.Strategy[0]
	}
	if len(order) > 0 {
		return order[0]
	}
	return "direct"
}
func (a *App) hasService(id string) bool {
	for _, s := range a.Catalog.Services {
		if s.ID == id {
			return true
		}
	}
	return false
}
func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
func methodNotAllowed(w http.ResponseWriter) {
	http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
}
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self'; script-src 'self'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'")
		next.ServeHTTP(w, r)
	})
}
func StartupMessage(addr, cfgPath, catalogPath string) string {
	return fmt.Sprintf("RAZVILKA %s listening on %s | config=%s | catalog=%s", Version, addr, cfgPath, catalogPath)
}
