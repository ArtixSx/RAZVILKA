package app

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ArtixSx/razvilka/internal/auditlog"
	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/community"
	"github.com/ArtixSx/razvilka/internal/components"
	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/customservices"
	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/devices"
	"github.com/ArtixSx/razvilka/internal/dnscontrol"
	"github.com/ArtixSx/razvilka/internal/engine"
	"github.com/ArtixSx/razvilka/internal/engineconfig"
	"github.com/ArtixSx/razvilka/internal/enginelab"
	"github.com/ArtixSx/razvilka/internal/evidence"
	"github.com/ArtixSx/razvilka/internal/privatebackup"
	"github.com/ArtixSx/razvilka/internal/profileexchange"
	"github.com/ArtixSx/razvilka/internal/providerprofile"
	"github.com/ArtixSx/razvilka/internal/routerstats"
	routecatalog "github.com/ArtixSx/razvilka/internal/routes"
	"github.com/ArtixSx/razvilka/internal/security"
	"github.com/ArtixSx/razvilka/internal/smartroute"
	"github.com/ArtixSx/razvilka/internal/sources"
	"github.com/ArtixSx/razvilka/internal/strategylab"
	"github.com/ArtixSx/razvilka/internal/systemprobe"
	"github.com/ArtixSx/razvilka/internal/telemetry"
	"github.com/ArtixSx/razvilka/internal/testlab"
	"github.com/ArtixSx/razvilka/internal/updatecheck"
	"github.com/ArtixSx/razvilka/internal/warp"
	"github.com/ArtixSx/razvilka/internal/z2kimport"
)

const Version = "0.15.1"
const defaultDataplaneApplyTimeout = 8 * time.Minute

type applyFailureAdvice struct {
	Code           string   `json:"code"`
	Title          string   `json:"title"`
	Message        string   `json:"message"`
	Resolution     string   `json:"resolution"`
	DraftPreserved bool     `json:"draft_preserved"`
	Retryable      bool     `json:"retryable"`
	Alternatives   []string `json:"alternatives,omitempty"`
}

type App struct {
	Store           *config.Store
	Catalog         catalog.Catalog
	Sources         *sources.Manager
	Telemetry       *telemetry.Store
	EngineConfigs   *engineconfig.Manager
	EngineLab       *enginelab.Manager
	StrategyLab     *strategylab.Manager
	Components      *components.Manager
	Community       *community.Manager
	CustomServices  *customservices.Manager
	Dataplane       *dataplane.Manager
	Devices         *devices.Manager
	DNS             *dnscontrol.Manager
	Warp            *warp.Manager
	TestLab         *testlab.Runner
	RouteProber     testlab.RouteProber
	SmartRoute      *smartroute.Manager
	Updates         *updatecheck.Manager
	Stats           *routerstats.Sampler
	Security        *security.Gate
	Audit           *auditlog.Journal
	Start           time.Time
	EffectiveListen string
	Z2KRoot         string
}

type serviceView struct {
	catalog.Service
	Custom         bool           `json:"custom"`
	Enabled        bool           `json:"enabled"`
	Mode           string         `json:"mode"`
	Route          string         `json:"route"`
	Planned        string         `json:"planned_engine"`
	Applied        bool           `json:"applied_enabled"`
	AppliedRoute   string         `json:"applied_route"`
	Sources        []string       `json:"sources,omitempty"`
	AppliedSources []string       `json:"applied_sources,omitempty"`
	Dirty          bool           `json:"dirty"`
	EvidenceLevel  evidence.Level `json:"evidence_level"`
	EvidenceRoute  string         `json:"evidence_route,omitempty"`
	EvidenceStatus string         `json:"evidence_status,omitempty"`
	EvidenceSource string         `json:"evidence_source,omitempty"`
	EvidenceAt     string         `json:"evidence_checked_at,omitempty"`
}

type serviceEvidenceView struct {
	Level     evidence.Level
	Route     string
	Status    string
	Source    string
	CheckedAt string
}

// serviceEvidenceSnapshot derives assurance only from applied state and
// observations. Desired and planned routes are deliberately absent: selecting
// an option in the UI must never make that route look proven.
func (a *App) serviceEvidenceSnapshot(cfg config.Config, services []catalog.Service) map[string]serviceEvidenceView {
	out := make(map[string]serviceEvidenceView, len(services))
	for _, service := range services {
		out[service.ID] = serviceEvidenceView{Level: evidence.Catalog, Status: "catalog-present", Source: "catalog"}
	}

	// AUTO is resolved from the last committed journal only. A newly calculated
	// plan is intent, not evidence of the route currently carrying traffic.
	committedRoutes := map[string]string{}
	if a.Dataplane != nil {
		if plan, exists, err := a.Dataplane.Committed(); err == nil && exists && plan.State == "committed" && plan.Revision == cfg.AppliedRevision {
			for _, route := range plan.Routes {
				committedRoutes[route.ServiceID] = route.Resolved
			}
		}
	}

	engineByID := map[string]engine.Status{}
	for _, status := range (engine.Detector{}).Inventory() {
		engineByID[status.ID] = status
	}
	effectiveRoute := map[string]string{}
	for serviceID, applied := range cfg.AppliedServices {
		if !applied.Enabled {
			continue
		}
		route := selectedRoute(applied)
		if route == "auto" {
			route = committedRoutes[serviceID]
		}
		effectiveRoute[serviceID] = route
		adapter := dataplane.AdapterID(route)
		if adapter == "" || adapter == "direct" {
			continue
		}
		status, exists := engineByID[adapter]
		if !exists {
			continue
		}
		observed := out[serviceID]
		observed.Route = route
		if status.Installed && status.Configured {
			observed.Level = evidence.Stronger(observed.Level, evidence.Configured)
			observed.Status = "engine-configured"
			observed.Source = "engine-inventory"
		}
		if status.Running {
			observed.Level = evidence.Stronger(observed.Level, evidence.Runtime)
			observed.Status = "engine-running"
			observed.Source = "process-and-interface-inventory"
		}
		out[serviceID] = observed
	}

	if a.TestLab == nil {
		return out
	}
	for _, result := range testlab.AggregateScenarios(a.TestLab.Snapshot(a.catalogSnapshot()).Current) {
		applied := cfg.AppliedServices[result.ServiceID]
		if !applied.Enabled {
			continue
		}
		route := effectiveRoute[result.ServiceID]
		level := result.AssuranceLevel()
		matchedRoute := result.Route == route && route != ""
		if result.Route == "current" {
			// A current-path request proves that the router attempted the request,
			// but cannot identify which bypass actually carried it.
			if level.AtLeast(evidence.Runtime) {
				level = evidence.Runtime
			}
		} else if !matchedRoute {
			continue
		}
		observed := out[result.ServiceID]
		stronger := evidence.Stronger(observed.Level, level)
		if stronger != observed.Level || stronger == level && result.CheckedAt >= observed.CheckedAt {
			observed.Level = stronger
			observed.Route = route
			observed.Status = result.Status
			observed.Source = result.EvidenceSource
			if observed.Source == "" {
				if result.Route == "current" {
					observed.Source = "current-path-probe"
				} else {
					observed.Source = "isolated-route-probe"
				}
			}
			observed.CheckedAt = result.CheckedAt
			out[result.ServiceID] = observed
		}
	}
	return out
}

func (a *App) Handler(static http.Handler) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/status", a.status)
	mux.HandleFunc("/api/v1/audit", a.auditSnapshot)
	mux.HandleFunc("/api/v1/auth/status", a.authStatus)
	mux.HandleFunc("/api/v1/auth/setup", a.authSetup)
	mux.HandleFunc("/api/v1/auth/login", a.authLogin)
	mux.HandleFunc("/api/v1/auth/logout", a.authLogout)
	mux.HandleFunc("/api/v1/auth/password", a.authPassword)
	mux.HandleFunc("/api/v1/auth/recover", a.authRecover)
	mux.HandleFunc("/api/v1/auth/recovery-key/rotate", a.authRecoveryKeyRotate)
	mux.HandleFunc("/api/v1/auth/sessions", a.authSessions)
	mux.HandleFunc("/api/v1/auth/sessions/", a.authSessionAction)
	mux.HandleFunc("/api/v1/engines", a.engines)
	mux.HandleFunc("/api/v1/engine-lab", a.engineLabReport)
	mux.HandleFunc("/api/v1/strategy-lab", a.strategyLabSnapshot)
	mux.HandleFunc("/api/v1/strategy-lab/candidates", a.strategyLabCandidates)
	mux.HandleFunc("/api/v1/strategy-lab/candidates/", a.strategyLabCandidateAction)
	mux.HandleFunc("/api/v1/strategy-lab/selections", a.strategyLabSelections)
	mux.HandleFunc("/api/v1/migrations/z2k/preview", a.z2kMigrationPreview)
	mux.HandleFunc("/api/v1/migrations/z2k/import-strategies", a.z2kMigrationImportStrategies)
	mux.HandleFunc("/api/v1/engine-configs", a.engineConfigs)
	mux.HandleFunc("/api/v1/engine-configs/", a.engineConfigAction)
	mux.HandleFunc("/api/v1/provider-profiles/preview", a.providerProfilePreview)
	mux.HandleFunc("/api/v1/provider-profiles/import", a.providerProfileImport)
	mux.HandleFunc("/api/v1/components", a.componentList)
	mux.HandleFunc("/api/v1/components/", a.componentAction)
	mux.HandleFunc("/api/v1/warp", a.warpStatus)
	mux.HandleFunc("/api/v1/warp/", a.warpAction)
	mux.HandleFunc("/api/v1/testlab", a.testLabSnapshot)
	mux.HandleFunc("/api/v1/testlab/current", a.testLabCurrent)
	mux.HandleFunc("/api/v1/testlab/routes", a.testLabRoutes)
	mux.HandleFunc("/api/v1/smart-route", a.smartRouteStatus)
	mux.HandleFunc("/api/v1/dns", a.dnsStatus)
	mux.HandleFunc("/api/v1/dns/plan", a.dnsPlan)
	mux.HandleFunc("/api/v1/dns/draft", a.dnsDraft)
	mux.HandleFunc("/api/v1/dns/nextdns", a.dnsNextDNS)
	mux.HandleFunc("/api/v1/dns/custom", a.dnsCustom)
	mux.HandleFunc("/api/v1/dns/test", a.dnsTest)
	mux.HandleFunc("/api/v1/dns/discard", a.dnsDiscard)
	mux.HandleFunc("/api/v1/routes/options", a.routeOptions)
	mux.HandleFunc("/api/v1/services", a.services)
	mux.HandleFunc("/api/v1/services/", a.service)
	mux.HandleFunc("/api/v1/devices", a.deviceList)
	mux.HandleFunc("/api/v1/devices/", a.deviceItem)
	mux.HandleFunc("/api/v1/custom-services", a.customServiceList)
	mux.HandleFunc("/api/v1/custom-services/", a.customServiceItem)
	mux.HandleFunc("/api/v1/community/services", a.communityServices)
	mux.HandleFunc("/api/v1/community/services/", a.communityServiceAction)
	mux.HandleFunc("/api/v1/plan", a.plan)
	mux.HandleFunc("/api/v1/dataplane/status", a.dataplaneStatus)
	mux.HandleFunc("/api/v1/apply", a.apply)
	mux.HandleFunc("/api/v1/discard", a.discard)
	mux.HandleFunc("/api/v1/system", a.systemInfo)
	mux.HandleFunc("/api/v1/metrics", a.metrics)
	mux.HandleFunc("/api/v1/settings/safe-mode", a.safeModeSetting)
	mux.HandleFunc("/api/v1/update", a.updateStatus)
	mux.HandleFunc("/api/v1/diagnostics/domain", a.domainDiagnostic)
	mux.HandleFunc("/api/v1/diagnostics/report", a.diagnosticReport)
	mux.HandleFunc("/api/v1/config/export", a.configExport)
	mux.HandleFunc("/api/v1/profiles/export", a.profileExport)
	mux.HandleFunc("/api/v1/profiles/preview", a.profilePreview)
	mux.HandleFunc("/api/v1/profiles/import", a.profileImport)
	mux.HandleFunc("/api/v1/private-backups/export", a.privateBackupExport)
	mux.HandleFunc("/api/v1/private-backups/preview", a.privateBackupPreview)
	mux.HandleFunc("/api/v1/private-backups/import", a.privateBackupImport)
	mux.HandleFunc("/api/v1/connections", a.connections)
	mux.HandleFunc("/api/v1/connections/stream", a.connectionStream)
	mux.HandleFunc("/api/v1/sources", a.sourceList)
	mux.HandleFunc("/api/v1/sources/refresh", a.sourceRefreshAll)
	mux.HandleFunc("/api/v1/sources/", a.sourceAction)
	mux.Handle("/", noStoreUI(static))
	return securityHeaders(a.auditMiddleware(a.Security.Middleware(mux)))
}

type auditResponseWriter struct {
	http.ResponseWriter
	status int
}

func (writer *auditResponseWriter) WriteHeader(status int) {
	if writer.status != 0 {
		return
	}
	writer.status = status
	writer.ResponseWriter.WriteHeader(status)
}

func (writer *auditResponseWriter) Write(value []byte) (int, error) {
	if writer.status == 0 {
		writer.status = http.StatusOK
	}
	return writer.ResponseWriter.Write(value)
}

func (a *App) auditMiddleware(next http.Handler) http.Handler {
	if a.Audit == nil {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/api/") || r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodOptions {
			next.ServeHTTP(w, r)
			return
		}
		started := time.Now()
		actor := "anonymous"
		if a.Security != nil && a.Security.RecoveryAuthenticated(r) {
			actor = "recovery-key"
		} else if a.Security != nil && a.Security.Authenticated(r) {
			actor = a.Security.Username()
		}
		writer := &auditResponseWriter{ResponseWriter: w}
		next.ServeHTTP(writer, r)
		status := writer.status
		if status == 0 {
			status = http.StatusOK
		}
		outcome := "ok"
		if status == http.StatusUnauthorized || status == http.StatusForbidden {
			outcome = "denied"
		} else if status >= 400 {
			outcome = "failed"
		}
		_ = a.Audit.Append(auditlog.Event{Action: r.Method, Path: boundedAuditPath(r.URL.Path), Outcome: outcome, StatusCode: status, Actor: actor, RemoteIP: requestRemoteIP(r), DurationMS: time.Since(started).Milliseconds()})
	})
}

func boundedAuditPath(value string) string {
	value = strings.TrimSpace(value)
	if len(value) > 240 {
		return value[:240]
	}
	return value
}

func requestRemoteIP(request *http.Request) string {
	if request == nil {
		return "local"
	}
	if address, err := netip.ParseAddrPort(request.RemoteAddr); err == nil {
		return address.Addr().String()
	}
	if address, err := netip.ParseAddr(request.RemoteAddr); err == nil {
		return address.String()
	}
	return "unknown"
}

func (a *App) auditSnapshot(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	if a.Audit == nil {
		http.Error(w, "audit journal disabled", http.StatusServiceUnavailable)
		return
	}
	limit := 50
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 1 || parsed > 500 {
			http.Error(w, "limit must be between 1 and 500", http.StatusBadRequest)
			return
		}
		limit = parsed
	}
	writeJSON(w, http.StatusOK, a.Audit.Read(limit))
}

func noStoreUI(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The UI is embedded into the binary and versioned as one unit. Router
		// browsers are commonly left open for days, so stale HTML must never keep
		// referencing an older CSS/JS bundle after a transactional upgrade.
		w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
		w.Header().Set("Pragma", "no-cache")
		w.Header().Set("Expires", "0")
		w.Header().Set("X-RAZVILKA-UI-Version", Version)
		next.ServeHTTP(w, r)
	})
}

func (a *App) updateStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	if a.Updates == nil {
		http.Error(w, "application update checker is disabled", http.StatusServiceUnavailable)
		return
	}
	refresh, _ := strconv.ParseBool(r.URL.Query().Get("refresh"))
	writeJSON(w, http.StatusOK, a.Updates.Check(r.Context(), refresh))
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
	engines := engine.Visible((engine.Detector{}).All())
	running, installed := 0, 0
	for _, e := range engines {
		if e.Installed {
			installed++
		}
		if e.Running {
			running++
		}
	}
	readySources, sourceCount, sourceCatalogCount, sourceDownloadable, sourceReferences := 0, 0, 0, 0, 0
	if a.Sources != nil {
		ss := a.Sources.List()
		sourceCatalogCount = len(ss)
		for _, s := range ss {
			if s.Kind == "reference" {
				sourceReferences++
				continue
			}
			sourceDownloadable++
			if !s.Enabled {
				continue
			}
			sourceCount++
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
	dataplaneState := "never-applied"
	dataplaneRecoveryState := "not-required"
	dataplaneAdapters := 0
	dataplaneError := ""
	lastApplyFailure := ""
	liveActive := false
	if a.Dataplane != nil {
		if runtime, err := a.Dataplane.Status(); err != nil {
			// The public status endpoint deliberately exposes only a stable error
			// category: journal errors can contain local filesystem paths.
			dataplaneState = "journal-error"
			dataplaneRecoveryState = "failed"
			dataplaneError = "dataplane journal unavailable"
		} else if runtime.Exists && runtime.Plan != nil {
			latest := runtime.Plan
			dataplaneState = latest.State
			appliedPlan := runtime.CommittedPlan
			if appliedPlan != nil {
				dataplaneAdapters = len(appliedPlan.Adapters)
			}
			if appliedPlan != nil && runtime.Recovery != nil && runtime.Recovery.PlanID == appliedPlan.PlanID {
				dataplaneRecoveryState = runtime.Recovery.State
				liveActive = len(appliedPlan.Adapters) > 0 && runtime.Recovery.State == "recovered"
			} else if appliedPlan != nil && runtime.Execution != nil && runtime.Execution.PlanID == appliedPlan.PlanID {
				dataplaneRecoveryState = "current-process"
				liveActive = len(appliedPlan.Adapters) > 0 && runtime.Execution.State == "committed"
			}
			if latest.Revision == cfg.Revision && runtime.Execution != nil && runtime.Execution.PlanID == latest.PlanID && runtime.Execution.State == "rolled-back" {
				lastApplyFailure = classifyApplyFailure(runtime.Execution.Error).Code
			}
		}
	}
	evidenceCounts := map[string]int{}
	highestEvidence := evidence.None
	for _, proof := range a.serviceEvidenceSnapshot(cfg, a.catalogSnapshot().Services) {
		evidenceCounts[string(proof.Level)]++
		highestEvidence = evidence.Stronger(highestEvidence, proof.Level)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"name": "RAZVILKA", "version": Version, "process_id": os.Getpid(), "safe_mode": cfg.SafeMode,
		"auth_required": a.Security != nil, "authenticated": a.Security != nil && a.Security.Authenticated(r),
		"setup_required": a.Security != nil && a.Security.SetupRequired(), "username": securityUsername(a.Security),
		"uptime_seconds": int(time.Since(a.Start).Seconds()), "listen": effectiveListen(a.EffectiveListen, cfg.Listen),
		"enabled_services": enabled, "catalog_services": len(a.catalogSnapshot().Services),
		"engines_installed": installed, "engines_running": running,
		"sources_ready": readySources, "sources_total": sourceCount, "sources_catalog_total": sourceCatalogCount,
		"sources_downloadable": sourceDownloadable, "sources_reference": sourceReferences,
		"active_connections": activeConnections, "engine_config_drafts": configDrafts,
		"routing_pending_changes": a.Store.Dirty(), "engine_pending_changes": configDrafts > 0,
		"dataplane_state": dataplaneState, "dataplane_recovery_state": dataplaneRecoveryState, "dataplane_adapters": dataplaneAdapters, "dataplane_error": dataplaneError, "live_active": liveActive,
		"last_apply_failure":     lastApplyFailure,
		"highest_evidence_level": highestEvidence, "evidence_counts": evidenceCounts,
		"pending_changes": a.Store.Dirty() || configDrafts > 0, "revision": cfg.Revision, "applied_revision": cfg.AppliedRevision, "last_applied_at": cfg.LastAppliedAt,
	})
}

func (a *App) authStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"authenticated": a.Security != nil && a.Security.Authenticated(r), "using_recovery_key": a.Security != nil && a.Security.RecoveryAuthenticated(r), "setup_required": a.Security != nil && a.Security.SetupRequired(), "username": securityUsername(a.Security)})
}

func (a *App) authSetup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	if a.Security == nil {
		http.Error(w, "authentication is disabled", http.StatusServiceUnavailable)
		return
	}
	var in struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&in); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	session, err := a.Security.Setup(in.Username, in.Password, r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	security.SetSessionCookie(w, r, session)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "username": strings.TrimSpace(in.Username)})
}

func (a *App) authLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	if a.Security == nil {
		http.Error(w, "authentication is disabled", http.StatusServiceUnavailable)
		return
	}
	var in struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&in); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	session, err := a.Security.Login(in.Username, in.Password, r)
	if err != nil {
		if errors.Is(err, security.ErrLoginRateLimited) {
			w.Header().Set("Retry-After", "60")
			http.Error(w, "too many login attempts; try again later", http.StatusTooManyRequests)
			return
		}
		http.Error(w, "invalid username or password", http.StatusUnauthorized)
		return
	}
	security.SetSessionCookie(w, r, session)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "username": strings.TrimSpace(in.Username)})
}

func (a *App) authPassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		methodNotAllowed(w)
		return
	}
	if a.Security == nil {
		http.Error(w, "authentication is disabled", http.StatusServiceUnavailable)
		return
	}
	var in struct {
		Current  string `json:"current_password"`
		Password string `json:"new_password"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&in); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	session, err := a.Security.ChangePassword(in.Current, in.Password, r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	security.SetSessionCookie(w, r, session)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "all_previous_sessions_revoked": true})
}

func (a *App) authRecover(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	if a.Security == nil {
		http.Error(w, "authentication is disabled", http.StatusServiceUnavailable)
		return
	}
	var in struct {
		Username string `json:"username"`
		Password string `json:"new_password"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&in); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	session, err := a.Security.RecoverPassword(in.Username, in.Password, r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	security.SetSessionCookie(w, r, session)
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "username": strings.TrimSpace(in.Username), "all_previous_sessions_revoked": true})
}

func (a *App) authRecoveryKeyRotate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	if a.Security == nil {
		http.Error(w, "authentication is disabled", http.StatusServiceUnavailable)
		return
	}
	var in struct {
		Current string `json:"current_password"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&in); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	token, err := a.Security.RotateRecoveryToken(in.Current)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "recovery_key": token, "recovery_url": fmt.Sprintf("%s://%s/#recovery=%s", scheme, r.Host, token), "shown_once": true})
}

func (a *App) authSessions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	if a.Security == nil {
		http.Error(w, "authentication is disabled", http.StatusServiceUnavailable)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"sessions": a.Security.Sessions(r)})
}

func (a *App) authSessionAction(w http.ResponseWriter, r *http.Request) {
	if a.Security == nil {
		http.Error(w, "authentication is disabled", http.StatusServiceUnavailable)
		return
	}
	action := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/v1/auth/sessions/"), "/")
	if action == "revoke-others" {
		if r.Method != http.MethodPost {
			methodNotAllowed(w)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "revoked": a.Security.RevokeOtherSessions(r)})
		return
	}
	if r.Method != http.MethodDelete || action == "" {
		methodNotAllowed(w)
		return
	}
	if !a.Security.RevokeSession(action) {
		http.Error(w, "unknown session", http.StatusNotFound)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "id": action})
}

func (a *App) authLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	if a.Security != nil {
		a.Security.Logout(r)
	}
	security.ClearSessionCookie(w, r)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func securityUsername(gate *security.Gate) string {
	if gate == nil {
		return ""
	}
	return gate.Username()
}

func (a *App) engines(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	writeJSON(w, http.StatusOK, engine.Visible((engine.Detector{}).All()))
}

func (a *App) engineLabReport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	if a.EngineLab == nil {
		http.Error(w, "engine lab disabled", http.StatusServiceUnavailable)
		return
	}
	writeJSON(w, http.StatusOK, a.EngineLab.Inspect())
}

func (a *App) strategyLabSnapshot(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	if a.StrategyLab == nil {
		http.Error(w, "Strategy Lab disabled", http.StatusServiceUnavailable)
		return
	}
	writeJSON(w, http.StatusOK, a.StrategyLab.Snapshot())
}

func (a *App) strategyLabCandidates(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	if a.StrategyLab == nil {
		http.Error(w, "Strategy Lab disabled", http.StatusServiceUnavailable)
		return
	}
	var input struct {
		PoolID    string `json:"pool_id"`
		Name      string `json:"name"`
		Arguments string `json:"arguments"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&input); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	candidate, err := a.StrategyLab.AddCandidate(input.PoolID, input.Name, input.Arguments, "expert")
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, http.StatusCreated, candidate)
}

func (a *App) strategyLabCandidateAction(w http.ResponseWriter, r *http.Request) {
	if a.StrategyLab == nil {
		http.Error(w, "Strategy Lab disabled", http.StatusServiceUnavailable)
		return
	}
	path := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/v1/strategy-lab/candidates/"), "/")
	if r.Method == http.MethodDelete && path != "" && !strings.Contains(path, "/") {
		if err := a.StrategyLab.DeleteCandidate(path); err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "candidate_id": path, "draft_only": true})
		return
	}
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	id, action, ok := strings.Cut(path, "/")
	if !ok || id == "" || action != "validate" && action != "probe" {
		http.NotFound(w, r)
		return
	}
	if action == "probe" {
		var input struct {
			ServiceID string `json:"service_id"`
			IPFamily  string `json:"ip_family"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10)).Decode(&input); err != nil {
			http.Error(w, "invalid json", http.StatusBadRequest)
			return
		}
		var service catalog.Service
		found := false
		for _, candidate := range a.catalogSnapshot().Services {
			if candidate.ID == input.ServiceID {
				service, found = candidate, true
				break
			}
		}
		if !found || strings.TrimSpace(service.ProbeURL) == "" {
			http.Error(w, "service is unknown or has no probe URL", http.StatusBadRequest)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 18*time.Second)
		defer cancel()
		evidence, err := a.StrategyLab.Probe(ctx, id, strategylab.ProbeTarget{ServiceID: service.ID, ProbeURL: service.ProbeURL, IPFamily: input.IPFamily})
		if err != nil {
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}
		writeJSON(w, http.StatusOK, evidence)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	candidate, err := a.StrategyLab.Validate(ctx, id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, http.StatusOK, candidate)
}

func (a *App) strategyLabSelections(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	if a.StrategyLab == nil {
		http.Error(w, "Strategy Lab disabled", http.StatusServiceUnavailable)
		return
	}
	var input struct {
		Action      string `json:"action"`
		ServiceID   string `json:"service_id"`
		Protocol    string `json:"protocol"`
		IPFamily    string `json:"ip_family"`
		CandidateID string `json:"candidate_id"`
		Frozen      bool   `json:"frozen"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10)).Decode(&input); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	if input.Action == "reset" {
		if err := a.StrategyLab.ResetSelection(input.ServiceID, input.Protocol, input.IPFamily); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "action": "reset"})
		return
	}
	selection, err := a.StrategyLab.Select(input.ServiceID, input.Protocol, input.IPFamily, input.CandidateID, input.Frozen)
	if err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	writeJSON(w, http.StatusOK, selection)
}

func (a *App) z2kMigrationPreview(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	preview, err := (z2kimport.Scanner{Root: a.Z2KRoot}).Scan()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, preview)
}

func (a *App) z2kMigrationImportStrategies(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	if a.StrategyLab == nil {
		http.Error(w, "Strategy Lab disabled", http.StatusServiceUnavailable)
		return
	}
	var input struct {
		Confirm string `json:"confirm"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&input); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	if input.Confirm != "IMPORT_Z2K_STRATEGIES" {
		http.Error(w, "explicit z2k strategy import confirmation is required", http.StatusBadRequest)
		return
	}
	preview, err := (z2kimport.Scanner{Root: a.Z2KRoot}).Scan()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if !preview.Found {
		http.Error(w, "z2k is not installed at the configured read-only path", http.StatusNotFound)
		return
	}
	inputs := make([]strategylab.CandidateInput, 0, len(preview.Strategies))
	skipped := make([]map[string]any, 0)
	for _, strategy := range preview.Strategies {
		if !strategy.Compatible {
			skipped = append(skipped, map[string]any{"source": strategy.Source, "issues": strategy.Issues})
			continue
		}
		origin := "z2k:" + strings.TrimSpace(preview.Version) + ":" + strategy.Source
		inputs = append(inputs, strategylab.CandidateInput{PoolID: strategy.PoolID, Name: strategy.Name, Arguments: strategy.Arguments, Origin: origin})
	}
	if len(inputs) == 0 {
		writeJSON(w, http.StatusConflict, map[string]any{"error": "z2k has no compatible strategy files", "skipped": skipped, "warnings": preview.Warnings})
		return
	}
	imported, err := a.StrategyLab.AddCandidates(inputs)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"ok": true, "draft_only": true, "live_config_changed": false,
		"imported": imported, "skipped": skipped, "warnings": preview.Warnings,
		"not_imported": map[string]any{
			"extra_domains": len(preview.ExtraDomains), "auto_domains": len(preview.AutoDomains),
			"exclude_domains": len(preview.ExcludeDomains), "exclude_cidrs": len(preview.ExcludeCIDRs), "warp_cidrs": len(preview.WarpCIDRs), "state_rows": preview.StateRows,
		},
		"note": "Импортированы только совместимые стратегии-кандидаты. Каждая всё ещё требует нативный NFQWS2 --dry-run и изолированные повторные тесты.",
	})
}

func (a *App) componentList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	if a.Components == nil {
		http.Error(w, "component manager disabled", http.StatusServiceUnavailable)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 100*time.Second)
	defer cancel()
	views, err := a.Components.List(ctx, r.URL.Query().Get("refresh") == "true")
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	runtimes := engine.Detector{}.Inventory()
	for i := range views {
		for _, runtime := range runtimes {
			if views[i].ID != runtime.ID {
				continue
			}
			views[i].Configured = runtime.Configured
			views[i].Running = runtime.Running
			views[i].ExternalOwner = runtime.External
			if runtime.External && runtime.Installed {
				views[i].Installed = true
				views[i].State = "external-installed"
				if runtime.Running {
					views[i].State = "external-active"
				}
			}
			break
		}
	}
	writeJSON(w, http.StatusOK, views)
}

func (a *App) componentAction(w http.ResponseWriter, r *http.Request) {
	if a.Components == nil {
		http.Error(w, "component manager disabled", http.StatusServiceUnavailable)
		return
	}
	path := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/v1/components/"), "/")
	id, action, ok := strings.Cut(path, "/")
	if !ok || id == "" {
		http.NotFound(w, r)
		return
	}
	if action == "plan" {
		if r.Method != http.MethodGet {
			methodNotAllowed(w)
			return
		}
		requested := strings.TrimSpace(r.URL.Query().Get("action"))
		if requested == "" {
			requested = "install"
		}
		ctx, cancel := context.WithTimeout(r.Context(), 100*time.Second)
		defer cancel()
		plan, err := a.Components.Plan(ctx, id, requested, r.URL.Query().Get("refresh") == "true")
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		a.enrichComponentPlan(&plan)
		writeJSON(w, http.StatusOK, plan)
		return
	}
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	if action != "install" && action != "update" && action != "remove" {
		http.NotFound(w, r)
		return
	}
	planContext, cancelPlan := context.WithTimeout(r.Context(), 100*time.Second)
	plan, planErr := a.Components.Plan(planContext, id, action, false)
	cancelPlan()
	if planErr != nil {
		http.Error(w, planErr.Error(), http.StatusBadRequest)
		return
	}
	a.enrichComponentPlan(&plan)
	if !plan.Ready {
		writeJSON(w, http.StatusConflict, map[string]any{
			"error": "component lifecycle plan is blocked",
			"code":  "LIFECYCLE_PLAN_BLOCKED",
			"plan":  plan,
		})
		return
	}
	if blocker := a.componentRuntimeBlocker(id, action); blocker != nil {
		writeJSON(w, http.StatusConflict, blocker)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 100*time.Second)
	defer cancel()
	var result components.Result
	var err error
	if action == "remove" {
		result, err = a.Components.Remove(ctx, id)
	} else {
		result, err = a.Components.Apply(ctx, id)
	}
	if err != nil {
		if result.Output != "" {
			writeJSON(w, http.StatusBadGateway, map[string]any{"error": err.Error(), "output": result.Output})
		} else {
			http.Error(w, err.Error(), http.StatusBadGateway)
		}
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (a *App) enrichComponentPlan(plan *components.Plan) {
	if plan == nil {
		return
	}
	for _, runtime := range (engine.Detector{}).Inventory() {
		if runtime.ID != plan.Component {
			continue
		}
		if runtime.Running && (plan.Action == "update" || plan.Action == "remove") {
			plan.AddBlocker("RUNTIME_ACTIVE", "Обход сейчас активен", "Перенесите зависимые сервисы на другой маршрут, примените изменения и повторите операцию.")
		}
		if runtime.External {
			plan.AddBlocker("EXTERNAL_OWNER", "Обход и его сетевые ресурсы управляются внешним проектом", "Используйте мастер миграции ownership.")
		}
		break
	}
	if plan.Action == "remove" {
		desired, applied := a.componentServiceReferences(plan.Component)
		if len(desired) > 0 || len(applied) > 0 {
			message := "Компонент используется маршрутами сервисов"
			if len(applied) > 0 {
				message += ": " + strings.Join(applied, ", ")
			} else {
				message += ": " + strings.Join(desired, ", ")
			}
			plan.AddBlocker("SERVICE_DEPENDENCY", message, "Переключите сервисы на другой обход и выполните общий Apply.")
		}
	}
}

func (a *App) componentRuntimeBlocker(id, action string) map[string]any {
	for _, runtime := range (engine.Detector{}).Inventory() {
		if runtime.ID != id {
			continue
		}
		if runtime.External {
			return map[string]any{"error": "component is managed by an external owner; use migration", "component": id, "code": "EXTERNAL_OWNER"}
		}
		if runtime.Running && (action == "update" || action == "remove" || action == "install") {
			return map[string]any{"error": "component runtime is active; move its services to another route and Apply first", "component": id, "running": true, "code": "RUNTIME_ACTIVE"}
		}
		break
	}
	if action == "remove" {
		desired, applied := a.componentServiceReferences(id)
		if len(desired) > 0 || len(applied) > 0 {
			return map[string]any{"error": "component is referenced by service routes; move them and Apply first", "component": id, "code": "SERVICE_DEPENDENCY", "desired_services": desired, "applied_services": applied}
		}
	}
	return nil
}

func (a *App) componentServiceReferences(component string) (desired, applied []string) {
	if a.Store == nil {
		return nil, nil
	}
	cfg := a.Store.Get()
	for id, state := range cfg.Services {
		if state.Enabled && routeUsesComponent(state.Route, component) {
			desired = append(desired, id)
		}
	}
	for id, state := range cfg.AppliedServices {
		if state.Enabled && routeUsesComponent(state.Route, component) {
			applied = append(applied, id)
		}
	}
	sort.Strings(desired)
	sort.Strings(applied)
	return desired, applied
}

func routeUsesComponent(route, component string) bool {
	route = strings.ToLower(strings.TrimSpace(route))
	component = strings.ToLower(strings.TrimSpace(component))
	if route == component || strings.HasPrefix(route, component+":") {
		return true
	}
	return component == "usque" && (route == "warp" || route == "warp-masque")
}

func (a *App) warpStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	if a.Warp == nil {
		http.Error(w, "WARP manager disabled", http.StatusServiceUnavailable)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	writeJSON(w, http.StatusOK, a.Warp.Status(ctx))
}

func (a *App) warpAction(w http.ResponseWriter, r *http.Request) {
	if a.Warp == nil {
		http.Error(w, "WARP manager disabled", http.StatusServiceUnavailable)
		return
	}
	action := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/v1/warp/"), "/")
	switch action {
	case "generate":
		if r.Method != http.MethodPost {
			methodNotAllowed(w)
			return
		}
		var in struct {
			AcceptTOS bool `json:"accept_tos"`
			Fresh     bool `json:"fresh"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&in); err != nil {
			http.Error(w, "invalid json", http.StatusBadRequest)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 120*time.Second)
		defer cancel()
		result, err := a.Warp.Generate(ctx, in.AcceptTOS, in.Fresh)
		if err != nil {
			if errors.Is(err, warp.ErrTermsAcceptanceRequired) {
				http.Error(w, err.Error(), http.StatusPreconditionRequired)
				return
			}
			if errors.Is(err, warp.ErrRegistrationEndpointUnavailable) {
				writeJSON(w, http.StatusServiceUnavailable, map[string]any{
					"error": "Cloudflare не ответил на регистрацию WARP после трёх попыток.",
					"code":  "WARP_REGISTRATION_UNAVAILABLE", "retryable": true,
					"hint": "Проверьте доступ к api.cloudflareclient.com через текущий обход, повторите позже или загрузите готовый WireGuard/WARP-профиль.",
				})
				return
			}
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		writeJSON(w, http.StatusOK, result)
	case "import":
		if r.Method != http.MethodPost {
			methodNotAllowed(w)
			return
		}
		var in struct {
			Content string `json:"content"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 300<<10)).Decode(&in); err != nil {
			http.Error(w, "invalid json", http.StatusBadRequest)
			return
		}
		result, err := a.Warp.Import(in.Content)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, http.StatusOK, result)
	case "check":
		if r.Method != http.MethodPost {
			methodNotAllowed(w)
			return
		}
		result, err := a.Warp.CheckCandidate()
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, http.StatusOK, result)
	case "connectivity":
		if r.Method != http.MethodPost {
			methodNotAllowed(w)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 12*time.Second)
		defer cancel()
		writeJSON(w, http.StatusOK, a.Warp.CheckConnectivity(ctx))
	case "profile":
		if r.Method != http.MethodDelete {
			methodNotAllowed(w)
			return
		}
		result, err := a.Warp.DeleteProfile(a.Store.Get().SafeMode)
		if err != nil {
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}
		writeJSON(w, http.StatusOK, result)
	case "health/policy":
		if r.Method != http.MethodPut {
			methodNotAllowed(w)
			return
		}
		var policy warp.HealthPolicy
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&policy); err != nil {
			http.Error(w, "invalid json", http.StatusBadRequest)
			return
		}
		status, err := a.Warp.UpdateHealthPolicy(policy)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, http.StatusOK, status)
	case "health/check":
		if r.Method != http.MethodPost {
			methodNotAllowed(w)
			return
		}
		if a.TestLab == nil || a.RouteProber == nil {
			http.Error(w, "isolated route probe disabled", http.StatusServiceUnavailable)
			return
		}
		cfg := a.Store.Get()
		ids := []string{}
		for id, service := range cfg.AppliedServices {
			if service.Enabled && selectedRoute(service) == "warp-wg" {
				ids = append(ids, id)
			}
		}
		if len(ids) == 0 {
			http.Error(w, "no applied services are assigned to WARP WireGuard", http.StatusConflict)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
		defer cancel()
		results := a.TestLab.ProbeRoutes(ctx, a.catalogSnapshot(), ids, []string{"warp-wg"}, a.RouteProber)
		aggregated := testlab.AggregateScenarios(results)
		if a.SmartRoute != nil {
			_, _ = a.SmartRoute.Observe(aggregated)
		}
		evidence := make([]warp.HealthEvidence, 0, len(aggregated))
		for _, result := range aggregated {
			evidence = append(evidence, warp.HealthEvidence{ServiceID: result.ServiceID, Status: result.Status, RouteConfirmed: result.RouteConfirmed, Level: result.AssuranceLevel()})
		}
		decision, err := a.processWarpHealth(ctx, evidence)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"results": results, "health": decision,
			"note": "Счётчик политики WARP изменяется только при подтверждённой привязке запроса к интерфейсу WARP и маршруту ядра.",
		})
	default:
		http.NotFound(w, r)
	}
}

func (a *App) processWarpHealth(ctx context.Context, evidence []warp.HealthEvidence) (warp.HealthDecision, error) {
	decision, err := a.Warp.ObserveHealth(evidence)
	if err != nil || !decision.ShouldGenerate {
		return decision, err
	}
	if _, err := a.Warp.Generate(ctx, decision.Policy.AcceptTOS, true); err != nil {
		return decision, fmt.Errorf("automatic WARP candidate generation: %w", err)
	}
	decision.ShouldGenerate = false
	decision.Reason = "fresh-candidate-staged-awaiting-transactional-apply"
	if !decision.Policy.AutoApplyCandidate {
		return decision, nil
	}
	cfg := a.Store.Get()
	if cfg.SafeMode {
		decision.Reason = "fresh-candidate-staged-safe-mode-blocked-auto-apply"
		return decision, nil
	}
	if a.Store.Dirty() {
		decision.Reason = "fresh-candidate-staged-route-draft-blocked-auto-apply"
		return decision, nil
	}
	if other := a.stagedEngineFilesExcept("warp-wg", "main"); len(other) > 0 {
		decision.Reason = "fresh-candidate-staged-other-engine-drafts-blocked-auto-apply"
		return decision, nil
	}
	if a.Dataplane == nil {
		decision.Reason = "fresh-candidate-staged-dataplane-unavailable"
		return decision, nil
	}
	transaction, err := a.buildDataplanePlan(cfg, a.routeOptionsSnapshot())
	if err != nil {
		_ = a.Warp.RecordActivation(false, err.Error())
		return decision, fmt.Errorf("build automatic WARP transaction: %w", err)
	}
	if !transaction.Ready || transaction.Noop {
		decision.Reason = "fresh-candidate-staged-transaction-blocked"
		return decision, nil
	}
	execution, err := a.Dataplane.Apply(ctx, transaction, nil)
	if err != nil {
		_ = a.Warp.RecordActivation(false, err.Error())
		return decision, fmt.Errorf("automatic WARP transactional apply (%s): %w", execution.State, err)
	}
	if err := a.Warp.RecordActivation(true, ""); err != nil {
		return decision, fmt.Errorf("record automatic WARP activation: %w", err)
	}
	decision.Reason = "fresh-profile-activated"
	return decision, nil
}

func (a *App) stagedEngineFilesExcept(engineID, fileID string) []string {
	if a.EngineConfigs == nil {
		return nil
	}
	var out []string
	for _, engine := range a.EngineConfigs.List() {
		for _, file := range engine.Files {
			if file.Staged && (engine.ID != engineID || file.ID != fileID) {
				out = append(out, engine.ID+"/"+file.ID)
			}
		}
	}
	sort.Strings(out)
	return out
}

// StartBackground runs guarded route diagnostics, DNS policy refresh and WARP
// recovery. Automatic WARP activation is opt-in and uses the normal
// transactional dataplane with health checks and rollback.
func (a *App) StartBackground(ctx context.Context) {
	go func() {
		timer := time.NewTimer(2 * time.Minute)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		ticker := time.NewTicker(15 * time.Minute)
		defer ticker.Stop()
		round := 0
		for {
			round++
			if a.Dataplane != nil {
				refreshCtx, refreshCancel := context.WithTimeout(ctx, 90*time.Second)
				_, _ = a.Dataplane.RefreshCommitted(refreshCtx)
				refreshCancel()
			}
			a.backgroundWarpHealth(ctx)
			if round%2 == 1 {
				a.backgroundSmartRoute(ctx)
			}
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
}

func (a *App) backgroundWarpHealth(parent context.Context) {
	if a.Warp == nil || a.TestLab == nil || a.RouteProber == nil || !a.Warp.Health().Policy.Enabled {
		return
	}
	cfg := a.Store.Get()
	ids := make([]string, 0, 12)
	for id, service := range cfg.AppliedServices {
		if service.Enabled && selectedRoute(service) == "warp-wg" {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	if len(ids) == 0 {
		return
	}
	if len(ids) > 12 {
		ids = ids[:12]
	}
	ctx, cancel := context.WithTimeout(parent, 2*time.Minute)
	defer cancel()
	results := a.TestLab.ProbeRoutes(ctx, a.catalogSnapshot(), ids, []string{"warp-wg"}, a.RouteProber)
	aggregated := testlab.AggregateScenarios(results)
	if a.SmartRoute != nil {
		_, _ = a.SmartRoute.Observe(aggregated)
	}
	evidence := make([]warp.HealthEvidence, 0, len(aggregated))
	for _, result := range aggregated {
		evidence = append(evidence, warp.HealthEvidence{ServiceID: result.ServiceID, Status: result.Status, RouteConfirmed: result.RouteConfirmed, Level: result.AssuranceLevel()})
	}
	_, _ = a.processWarpHealth(ctx, evidence)
}

func (a *App) backgroundSmartRoute(parent context.Context) {
	if a.SmartRoute == nil || a.TestLab == nil || a.RouteProber == nil {
		return
	}
	cfg := a.Store.Get()
	checked := 0
	for _, service := range a.catalogSnapshot().Services {
		state := cfg.AppliedServices[service.ID]
		if !state.Enabled || selectedRoute(state) != "auto" {
			continue
		}
		routes := isolatedCandidates(service.Strategy)
		if len(routes) == 0 {
			continue
		}
		ctx, cancel := context.WithTimeout(parent, 45*time.Second)
		results := a.TestLab.ProbeRoutes(ctx, catalog.Catalog{Services: []catalog.Service{service}}, []string{service.ID}, routes, a.RouteProber)
		cancel()
		_, _ = a.SmartRoute.Observe(testlab.AggregateScenarios(results))
		checked++
		if checked >= 6 || parent.Err() != nil {
			return
		}
	}
}

func isolatedCandidates(strategy []string) []string {
	// NFQWS2 uses a serialized, destination/source-port scoped temporary chain;
	// only its exact per-request counter is accepted as Smart Route evidence.
	supported := map[string]bool{"direct": true, "nfqws2": true, "usque": true, "warp-wg": true, "sing-box": true, "xray": true, "amneziawg": true}
	routes := []string{"direct"}
	seen := map[string]bool{"direct": true}
	for _, route := range strategy {
		if supported[route] && !seen[route] {
			routes = append(routes, route)
			seen[route] = true
		}
		if len(routes) == 4 {
			break
		}
	}
	return routes
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
			var content engineconfig.Content
			var err error
			if r.URL.Query().Get("expert") == "true" {
				if a.Security == nil || !a.Security.Authenticated(r) {
					http.Error(w, "authentication required to reveal expert config", http.StatusUnauthorized)
					return
				}
				content, err = a.EngineConfigs.ReadExpert(engineID, fileID)
			} else {
				content, err = a.EngineConfigs.Read(engineID, fileID)
			}
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
	case "guided":
		switch r.Method {
		case http.MethodGet:
			view, err := a.EngineConfigs.Guided(engineID, fileID)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			writeJSON(w, http.StatusOK, view)
		case http.MethodPut:
			var in struct {
				Values map[string]string `json:"values"`
			}
			if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 256<<10)).Decode(&in); err != nil {
				http.Error(w, "invalid json", http.StatusBadRequest)
				return
			}
			content, err := a.EngineConfigs.StageGuided(engineID, fileID, in.Values)
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
		writeJSON(w, http.StatusConflict, map[string]any{
			"ok":              false,
			"error":           "Отдельное применение конфигурации отключено: используйте общий транзакционный Apply.",
			"resolution":      "Назначьте включённый сервис этому обходу, проверьте план и нажмите «Применить» в верхней панели.",
			"engine_id":       engineID,
			"file_id":         fileID,
			"pending_changes": true,
		})
	default:
		http.NotFound(w, r)
	}
}

func (a *App) providerProfilePreview(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	input, ok := decodeProviderProfileRequest(w, r)
	if !ok {
		return
	}
	result, err := providerprofile.ParseProfile(input.Profile)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true, "draft_only": true, "preview": result.Preview,
		"note": "Ключи и пароли не показываются. Предпросмотр ничего не сохраняет; исходный пакет нормализуется в безопасный конфиг RAZVILKA.",
	})
}

func (a *App) providerProfileImport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	if a.EngineConfigs == nil {
		http.Error(w, "engine config manager disabled", http.StatusServiceUnavailable)
		return
	}
	input, ok := decodeProviderProfileRequest(w, r)
	if !ok {
		return
	}
	if input.Confirm != "IMPORT_REMOTE_PROFILE" {
		http.Error(w, "явно подтвердите импорт удалённого профиля", http.StatusPreconditionRequired)
		return
	}
	result, err := providerprofile.ParseProfileWithSelection(input.Profile, input.SelectedIndex)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	validation := engineconfig.ValidatePrivateContent("sing-box", "main", string(result.Config))
	if !validation.OK {
		http.Error(w, validation.Output, http.StatusBadRequest)
		return
	}
	draft, err := a.EngineConfigs.Stage("sing-box", "main", string(result.Config))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	native := a.EngineConfigs.Validate("sing-box", "main")
	writeJSON(w, http.StatusOK, map[string]any{
		"ok": native.OK, "draft_only": true, "preview": result.Preview,
		"draft": draft, "validation": native,
		"note": "Пакет узлов сохранён только в черновик Sing-box. Назначьте сервис, проверьте план и выполните общий Apply.",
	})
}

type providerProfileRequest struct {
	URI           string `json:"uri"`
	Profile       string `json:"profile"`
	Confirm       string `json:"confirm"`
	SelectedIndex int    `json:"selected_index"`
}

func decodeProviderProfileRequest(w http.ResponseWriter, r *http.Request) (providerProfileRequest, bool) {
	var input providerProfileRequest
	reader := http.MaxBytesReader(w, r.Body, 2*providerprofile.MaxProfileBytes+(8<<10))
	decoder := json.NewDecoder(reader)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&input); err != nil {
		http.Error(w, "некорректный запрос профиля", http.StatusBadRequest)
		return providerProfileRequest{}, false
	}
	profile := input.Profile
	if profile == "" {
		profile = input.URI
	}
	input.Profile = profile
	return input, true
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
	writeJSON(w, http.StatusOK, a.TestLab.Snapshot(a.catalogSnapshot()))
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
	results := a.TestLab.ProbeCurrent(ctx, a.catalogSnapshot(), ids)
	writeJSON(w, http.StatusOK, map[string]any{
		"mode": "current-routing", "safe_mode": a.Store.Get().SafeMode, "results": results,
		"note": "This probe measures the currently applied routing and is not route-confirmed. Use the isolated route comparison for Smart Route and WARP policy evidence.",
	})
}

func (a *App) testLabRoutes(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	if a.TestLab == nil || a.RouteProber == nil {
		http.Error(w, "isolated route probe disabled", http.StatusServiceUnavailable)
		return
	}
	var in struct {
		Services []string `json:"services"`
		Routes   []string `json:"routes"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 32<<10)).Decode(&in); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	if len(in.Services) == 0 || len(in.Services) > 12 || len(in.Routes) == 0 || len(in.Routes) > 8 {
		http.Error(w, "select 1..12 services and 1..8 routes", http.StatusBadRequest)
		return
	}
	services := make([]string, 0, len(in.Services))
	seenServices := map[string]bool{}
	for _, id := range in.Services {
		if !a.hasService(id) {
			http.Error(w, "unknown service: "+id, http.StatusBadRequest)
			return
		}
		if !seenServices[id] {
			seenServices[id] = true
			services = append(services, id)
		}
	}
	knownRoutes := map[string]bool{}
	for _, option := range a.routeOptionsSnapshot() {
		if option.ID != "auto" {
			knownRoutes[option.ID] = true
		}
	}
	routes := make([]string, 0, len(in.Routes))
	seenRoutes := map[string]bool{}
	for _, route := range in.Routes {
		if !knownRoutes[route] {
			http.Error(w, "unknown route: "+route, http.StatusBadRequest)
			return
		}
		if !seenRoutes[route] {
			seenRoutes[route] = true
			routes = append(routes, route)
		}
	}
	controlAdded := false
	if !seenRoutes["direct"] {
		for _, route := range routes {
			if route != "direct" {
				routes = append([]string{"direct"}, routes...)
				controlAdded = true
				break
			}
		}
	}
	ctx, cancel := context.WithTimeout(r.Context(), 90*time.Second)
	defer cancel()
	results := a.TestLab.ProbeRoutes(ctx, a.catalogSnapshot(), services, routes, a.RouteProber)
	aggregated := testlab.AggregateScenarios(results)
	assessments := testlab.AssessComparisons(results)
	decisions := []smartroute.Decision{}
	if a.SmartRoute != nil {
		var err error
		decisions, err = a.SmartRoute.Observe(aggregated)
		if err != nil {
			http.Error(w, "save Smart Route evidence: "+err.Error(), http.StatusInternalServerError)
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"mode": "isolated-route", "safe_mode": a.Store.Get().SafeMode, "results": results, "summary": aggregated, "decisions": decisions, "assessments": assessments, "control_added": controlAdded,
		"note": "Изолированная проверка не меняет DNS или маршрут по умолчанию. DIRECT добавляется как контроль: только его подтверждённый отказ доказывает необходимость обхода. Для NFQWS2 создаётся временная цепочка только для одного destination/source-port и удаляется после теста; остальные обходы подтверждаются явным SOCKS-транспортом либо привязкой сокета к интерфейсу.",
	})
}

func (a *App) smartRouteStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	if a.SmartRoute == nil {
		http.Error(w, "Smart Route disabled", http.StatusServiceUnavailable)
		return
	}
	writeJSON(w, http.StatusOK, a.SmartRoute.Snapshot())
}

func (a *App) dnsStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	if a.DNS == nil {
		http.Error(w, "DNS control disabled", http.StatusServiceUnavailable)
		return
	}
	writeJSON(w, http.StatusOK, a.DNS.Snapshot())
}

func (a *App) dnsPlan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	if a.DNS == nil {
		http.Error(w, "DNS control disabled", http.StatusServiceUnavailable)
		return
	}
	listener := ""
	if a.EngineLab != nil {
		for _, conflict := range a.EngineLab.Inspect().ApplyConflicts([]string{"dns-control"}) {
			if conflict.Kind == "dns" {
				listener = conflict.SystemUse
				break
			}
		}
	}
	writeJSON(w, http.StatusOK, a.DNS.Plan(listener))
}

func (a *App) dnsDraft(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		methodNotAllowed(w)
		return
	}
	if a.DNS == nil {
		http.Error(w, "DNS control disabled", http.StatusServiceUnavailable)
		return
	}
	var input struct {
		ProfileID string `json:"profile_id"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&input); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	if err := a.DNS.SetDraft(input.ProfileID); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, http.StatusOK, a.DNS.Snapshot())
}

func (a *App) dnsNextDNS(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		methodNotAllowed(w)
		return
	}
	if a.DNS == nil {
		http.Error(w, "DNS control disabled", http.StatusServiceUnavailable)
		return
	}
	var input struct {
		ProfileID string `json:"profile_id"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024)).Decode(&input); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	if err := a.DNS.SetNextDNSProfileID(input.ProfileID); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, http.StatusOK, a.DNS.Snapshot())
}

func (a *App) dnsCustom(w http.ResponseWriter, r *http.Request) {
	if a.DNS == nil {
		http.Error(w, "DNS control disabled", http.StatusServiceUnavailable)
		return
	}
	switch r.Method {
	case http.MethodPut:
		var input dnscontrol.CustomProviderInput
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&input); err != nil {
			http.Error(w, "invalid json", http.StatusBadRequest)
			return
		}
		if err := a.DNS.SetCustomProvider(input); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	case http.MethodDelete:
		if err := a.DNS.ClearCustomProvider(); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	default:
		methodNotAllowed(w)
		return
	}
	writeJSON(w, http.StatusOK, a.DNS.Snapshot())
}

func (a *App) dnsTest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	if a.DNS == nil {
		http.Error(w, "DNS control disabled", http.StatusServiceUnavailable)
		return
	}
	var input struct {
		ProfileID string `json:"profile_id"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&input); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	results, err := a.DNS.Probe(r.Context(), input.ProfileID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "profile_id": input.ProfileID, "results": results, "note": "Проверка отдельно обращается к заявленным UDP, TCP, DoH и DoT endpoint. Она не меняет DNS роутера; DoH/DoT могут использовать системный DNS только для bootstrap имени провайдера и не доказывают отсутствие утечки LAN-клиентов."})
}

func (a *App) dnsDiscard(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	if a.DNS == nil {
		http.Error(w, "DNS control disabled", http.StatusServiceUnavailable)
		return
	}
	if err := a.DNS.Discard(); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, a.DNS.Snapshot())
}

func (a *App) routeOptions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	writeJSON(w, http.StatusOK, a.routeOptionsSnapshot())
}

func (a *App) services(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	cfg := a.Store.Get()
	services := a.catalogSnapshot().Services
	options := a.routeOptionsSnapshot()
	observedEvidence := a.serviceEvidenceSnapshot(cfg, services)
	views := make([]serviceView, 0, len(services))
	for _, s := range services {
		st := cfg.Services[s.ID]
		applied := cfg.AppliedServices[s.ID]
		selected := selectedRoute(st)
		planned := selected
		if selected == "auto" {
			planned = a.resolveAutoWithOptions(s, cfg.EngineOrder, options)
		}
		appliedRoute := selectedRoute(applied)
		dirty := st.Enabled != applied.Enabled || selected != appliedRoute || !stringSlicesEqual(st.Sources, applied.Sources)
		custom := a.CustomServices != nil && a.CustomServices.Has(s.ID)
		proof := observedEvidence[s.ID]
		views = append(views, serviceView{Service: s, Custom: custom, Enabled: st.Enabled, Mode: selected, Route: selected, Planned: planned, Applied: applied.Enabled, AppliedRoute: appliedRoute, Sources: append([]string(nil), st.Sources...), AppliedSources: append([]string(nil), applied.Sources...), Dirty: dirty, EvidenceLevel: proof.Level, EvidenceRoute: proof.Route, EvidenceStatus: proof.Status, EvidenceSource: proof.Source, EvidenceAt: proof.CheckedAt})
	}
	sort.Slice(views, func(i, j int) bool {
		if views[i].Category == views[j].Category {
			return views[i].Name < views[j].Name
		}
		return views[i].Category < views[j].Category
	})
	writeJSON(w, http.StatusOK, views)
}

type devicePolicyView struct {
	ServiceID   string `json:"service_id"`
	ServiceName string `json:"service_name"`
	Route       string `json:"route"`
	Scope       string `json:"scope"`
}

type deviceView struct {
	devices.Device
	Policies []devicePolicyView `json:"policies"`
}

func (a *App) deviceList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	if a.Devices == nil {
		writeJSON(w, http.StatusOK, []deviceView{})
		return
	}
	catalogByID := map[string]catalog.Service{}
	for _, service := range a.catalogSnapshot().Services {
		catalogByID[service.ID] = service
	}
	cfg := a.Store.Get()
	discovered := a.Devices.List(r.Context())
	views := make([]deviceView, 0, len(discovered))
	for _, device := range discovered {
		view := deviceView{Device: device, Policies: []devicePolicyView{}}
		for serviceID, state := range cfg.Services {
			if !state.Enabled {
				continue
			}
			scope := "all-devices"
			if len(state.Sources) > 0 {
				if !deviceMatchesSources(device.IPs, state.Sources) {
					continue
				}
				scope = "selected-device"
			}
			service := catalogByID[serviceID]
			name := service.Name
			if name == "" {
				name = serviceID
			}
			view.Policies = append(view.Policies, devicePolicyView{ServiceID: serviceID, ServiceName: name, Route: selectedRoute(state), Scope: scope})
		}
		sort.Slice(view.Policies, func(i, j int) bool { return view.Policies[i].ServiceName < view.Policies[j].ServiceName })
		views = append(views, view)
	}
	writeJSON(w, http.StatusOK, views)
}

func (a *App) deviceItem(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		methodNotAllowed(w)
		return
	}
	if a.Devices == nil {
		http.Error(w, "device manager disabled", http.StatusServiceUnavailable)
		return
	}
	id, err := url.PathUnescape(strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/v1/devices/"), "/"))
	if err != nil || id == "" {
		http.Error(w, "invalid device id", http.StatusBadRequest)
		return
	}
	var input struct {
		Name  string `json:"name"`
		Group string `json:"group"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&input); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	device, err := a.Devices.Update(id, input.Name, input.Group)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, http.StatusOK, device)
}

func deviceMatchesSources(ips, sources []string) bool {
	for _, rawIP := range ips {
		address, err := netip.ParseAddr(rawIP)
		if err != nil {
			continue
		}
		address = address.Unmap()
		for _, rawSource := range sources {
			if source, err := netip.ParseAddr(rawSource); err == nil && source.Unmap() == address {
				return true
			}
			if prefix, err := netip.ParsePrefix(rawSource); err == nil && prefix.Contains(address) {
				return true
			}
		}
	}
	return false
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
	if !routecatalog.ValidWithOptions(selected, a.routeOptionsSnapshot()) {
		http.Error(w, "invalid route", http.StatusBadRequest)
		return
	}
	in.Route = selected
	in.Mode = selected
	normalizedSources, err := config.NormalizeSources(in.Sources)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	in.Sources = normalizedSources
	if err := a.Store.UpdateService(id, in); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "id": id, "state": in})
}

func (a *App) customServiceList(w http.ResponseWriter, r *http.Request) {
	if a.CustomServices == nil {
		http.Error(w, "custom services disabled", http.StatusServiceUnavailable)
		return
	}
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, a.CustomServices.List())
	case http.MethodPost:
		var service catalog.Service
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 512<<10)).Decode(&service); err != nil {
			http.Error(w, "invalid json", http.StatusBadRequest)
			return
		}
		reserved := make(map[string]bool, len(a.Catalog.Services))
		for _, builtIn := range a.Catalog.Services {
			reserved[builtIn.ID] = true
		}
		created, err := a.CustomServices.Create(service, reserved)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, http.StatusCreated, created)
	default:
		methodNotAllowed(w)
	}
}

func (a *App) customServiceItem(w http.ResponseWriter, r *http.Request) {
	if a.CustomServices == nil {
		http.Error(w, "custom services disabled", http.StatusServiceUnavailable)
		return
	}
	id := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/v1/custom-services/"), "/")
	if id == "" || !a.CustomServices.Has(id) {
		http.Error(w, "unknown custom service", http.StatusNotFound)
		return
	}
	switch r.Method {
	case http.MethodPut:
		var service catalog.Service
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 512<<10)).Decode(&service); err != nil {
			http.Error(w, "invalid json", http.StatusBadRequest)
			return
		}
		updated, err := a.CustomServices.Update(id, service)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, http.StatusOK, updated)
	case http.MethodDelete:
		if err := a.CustomServices.Delete(id); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if err := a.Store.DeleteService(id); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "id": id})
	default:
		methodNotAllowed(w)
	}
}

func (a *App) communityServices(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	if a.Community == nil {
		http.Error(w, "community catalog disabled", http.StatusServiceUnavailable)
		return
	}
	imported := func(id string) bool { return a.CustomServices != nil && a.CustomServices.Has(id) }
	writeJSON(w, http.StatusOK, a.Community.Search(r.URL.Query().Get("q"), imported))
}

func (a *App) communityServiceAction(w http.ResponseWriter, r *http.Request) {
	if a.Community == nil || a.CustomServices == nil {
		http.Error(w, "community or custom service catalog disabled", http.StatusServiceUnavailable)
		return
	}
	path := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/v1/community/services/"), "/")
	id, action, ok := strings.Cut(path, "/")
	if !ok || id == "" {
		http.NotFound(w, r)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 45*time.Second)
	defer cancel()
	switch action {
	case "preview":
		if r.Method != http.MethodGet {
			methodNotAllowed(w)
			return
		}
		preview, err := a.Community.Preview(ctx, id, a.catalogSnapshot().Services, r.URL.Query().Get("refresh") == "true")
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				http.Error(w, "unknown community service", http.StatusNotFound)
			} else {
				http.Error(w, err.Error(), http.StatusBadGateway)
			}
			return
		}
		writeJSON(w, http.StatusOK, preview)
	case "import":
		if r.Method != http.MethodPost {
			methodNotAllowed(w)
			return
		}
		var in struct {
			AllowConflicts bool `json:"allow_conflicts"`
			Refresh        bool `json:"refresh"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&in); err != nil {
			http.Error(w, "invalid json", http.StatusBadRequest)
			return
		}
		preview, err := a.Community.Preview(ctx, id, a.catalogSnapshot().Services, in.Refresh)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		if len(preview.Conflicts) > 0 && !in.AllowConflicts {
			writeJSON(w, http.StatusConflict, map[string]any{"error": "community service conflicts with existing rules", "conflicts": preview.Conflicts})
			return
		}
		reserved := make(map[string]bool, len(a.Catalog.Services))
		for _, builtIn := range a.Catalog.Services {
			reserved[builtIn.ID] = true
		}
		customID := "custom-" + preview.Service.ID
		var saved catalog.Service
		created := !a.CustomServices.Has(customID)
		if created {
			saved, err = a.CustomServices.Create(preview.Service, reserved)
		} else {
			saved, err = a.CustomServices.Update(customID, preview.Service)
		}
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		status := http.StatusOK
		if created {
			status = http.StatusCreated
		}
		writeJSON(w, status, map[string]any{"service": saved, "provenance": saved.Provenance, "updated": !created, "conflicts_accepted": in.AllowConflicts && len(preview.Conflicts) > 0})
	default:
		http.NotFound(w, r)
	}
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
	scope, engineID, scopeErr := changeScopeFromRequest(r)
	if scopeErr != nil {
		http.Error(w, scopeErr.Error(), http.StatusBadRequest)
		return
	}
	cfg := a.Store.Get()
	options := a.routeOptionsSnapshot()
	var rows []map[string]any
	for _, s := range a.catalogSnapshot().Services {
		st := cfg.Services[s.ID]
		if !st.Enabled {
			continue
		}
		selected := selectedRoute(st)
		resolved := selected
		if selected == "auto" {
			resolved = a.resolveAutoWithOptions(s, cfg.EngineOrder, options)
		}
		rows = append(rows, map[string]any{
			"service": s.Name, "id": s.ID, "selected_route": selected, "engine": resolved,
			"domains": len(s.Domains), "cidrs": len(s.CIDRs), "source_refs": s.SourceRefs,
		})
	}
	transaction, err := a.buildDataplanePlanForScope(cfg, options, scope, engineID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	// A freshly built plan describes current intent. Reuse observed evidence
	// only when it is byte-for-byte the same input (digest + revision) as the
	// last committed plan. Drafts and newly selected routes therefore always
	// start unproven, while the UI can still show proof for the active plan.
	if a.Dataplane != nil {
		if committed, exists, committedErr := a.Dataplane.Committed(); committedErr == nil && exists && committed.State == "committed" && committed.Digest == transaction.Digest && committed.Revision == transaction.Revision {
			transaction.State = committed.State
			transaction.ObservedEvidence = committed.ObservedEvidence
			transaction.EvidenceNote = committed.EvidenceNote
			transaction.RouteEvidence = append([]dataplane.RouteEvidence(nil), committed.RouteEvidence...)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"safe_mode":   cfg.SafeMode,
		"scope":       scope,
		"note":        "v0.15.1: service and device routing changes apply independently from unrelated engine drafts. Safe Mode remains the default.",
		"routes":      rows,
		"transaction": transaction,
	})
}

func (a *App) dataplaneStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	if a.Dataplane == nil {
		writeJSON(w, http.StatusOK, map[string]any{"exists": false, "state": "not-configured"})
		return
	}
	status, err := a.Dataplane.Status()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, status)
}

func (a *App) apply(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	scope, engineID, scopeErr := changeScopeFromRequest(r)
	if scopeErr != nil {
		http.Error(w, scopeErr.Error(), http.StatusBadRequest)
		return
	}
	if scope == changeScopeEngine && a.Store.Dirty() {
		writeJSON(w, http.StatusConflict, map[string]any{
			"ok": false, "scope": scope, "pending_changes": a.pendingChanges(), "scope_pending_changes": true,
			"error": "routing changes must be applied first",
			"note":  "Сначала примените или отмените изменения на вкладке «Сервисы». Конфигурация обхода сохранена и не потеряна.",
		})
		return
	}
	cfg := a.Store.Get()
	transaction, err := a.buildDataplanePlanForScope(cfg, a.routeOptionsSnapshot(), scope, engineID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	record := func() bool {
		if a.Dataplane == nil {
			return true
		}
		if err := a.Dataplane.Record(transaction); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return false
		}
		return true
	}
	// A direct-only plan is an honest no-op and can be committed in Safe Mode.
	// Any non-direct plan is only reviewed there and remains dirty until a live
	// transaction has activated and verified every adapter.
	if cfg.SafeMode && !transaction.Noop {
		transaction.State = "reviewed"
		transaction.Note = "План проверен в Safe Mode. Желаемое состояние сохранено, но live-маршруты не изменены."
		if !record() {
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"ok": true, "reviewed": true, "safe_mode": true, "scope": scope, "pending_changes": true, "scope_pending_changes": true, "live_applied": false,
			"note": transaction.Note, "transaction": transaction,
		})
		return
	}
	if !cfg.SafeMode && !transaction.Ready {
		if !record() {
			return
		}
		writeJSON(w, http.StatusConflict, map[string]any{
			"ok": false, "safe_mode": false, "scope": scope, "pending_changes": true, "scope_pending_changes": true, "live_applied": false,
			"error": "dataplane transaction is blocked", "transaction": transaction,
		})
		return
	}
	if !cfg.SafeMode && !transaction.Noop {
		if a.Dataplane == nil {
			http.Error(w, "dataplane runtime is not configured", http.StatusServiceUnavailable)
			return
		}
		applyContext, cancelApply := context.WithTimeout(r.Context(), defaultDataplaneApplyTimeout)
		defer cancelApply()
		execution, applyErr := a.Dataplane.Apply(applyContext, transaction, a.Store.ApplyDraftWithRollback)
		if applyErr != nil {
			failure := classifyApplyFailure(applyErr.Error())
			writeJSON(w, http.StatusConflict, map[string]any{
				"ok": false, "safe_mode": false, "scope": scope, "pending_changes": a.pendingChanges(), "scope_pending_changes": a.scopePendingChanges(scope, engineID), "live_applied": false,
				"error": applyErr.Error(), "note": failure.Message, "failure": failure, "transaction": transaction, "execution": execution,
			})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"ok": true, "safe_mode": false, "scope": scope, "pending_changes": a.pendingChanges(), "scope_pending_changes": a.scopePendingChanges(scope, engineID), "live_applied": true,
			"note": "Dataplane activated, health-checked and committed.", "transaction": transaction, "execution": execution,
		})
		return
	}
	if err := a.Store.ApplyDraft(); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	cfg = a.Store.Get()
	note := "Желаемое состояние подтверждено: все выбранные маршруты direct, изменение dataplane не требовалось."
	liveApplied := transaction.Noop
	transaction.State = "committed"
	transaction.Note = note
	if !record() {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "safe_mode": cfg.SafeMode, "scope": scope, "pending_changes": a.pendingChanges(), "scope_pending_changes": a.scopePendingChanges(scope, engineID), "live_applied": liveApplied, "note": note, "transaction": transaction})
}

func classifyApplyFailure(message string) applyFailureAdvice {
	advice := applyFailureAdvice{
		Code: "DATAPLANE_APPLY_FAILED", Title: "Изменения не применены",
		Message:        "Проверка нового маршрута не прошла. Рабочая конфигурация автоматически восстановлена, а черновик сохранён.",
		Resolution:     "Откройте технические детали, исправьте причину и повторите применение либо отмените черновик.",
		DraftPreserved: true, Retryable: true,
	}
	lower := strings.ToLower(message)
	if strings.Contains(lower, "warp wireguard handshake was not confirmed") || strings.Contains(lower, "warp handshake was not confirmed") {
		advice.Code = "WARP_WIREGUARD_HANDSHAKE"
		advice.Title = "WARP WireGuard не подключился"
		advice.Message = "Cloudflare не подтвердил WireGuard-handshake. RAZVILKA проверила настроенный и резервные UDP-порты, затем безопасно вернула прежний интернет; черновик сохранён."
		advice.Resolution = "Если повтор не помогает, используйте WARP · MASQUE либо импортируйте отдельный AmneziaWG/VLESS-профиль. Профиль WARP нельзя преобразовать в AmneziaWG без совместимого сервера."
		advice.Alternatives = []string{"usque", "amneziawg", "sing-box"}
	} else if strings.Contains(lower, "usque probe") || (strings.Contains(lower, "masque") && strings.Contains(lower, "timeout")) {
		advice.Code = "WARP_MASQUE_SERVICE_TIMEOUT"
		advice.Title = "WARP MASQUE подключился, но сервис не ответил"
		advice.Message = "Сессия с Cloudflare была создана, однако проверочный запрос выбранного сервиса не прошёл через туннель. RAZVILKA вернула прежние маршруты; интернет роутера не изменён."
		advice.Resolution = "Создайте новую MASQUE-сессию и повторите один раз. Если результат тот же, сеть провайдера блокирует или повреждает трафик WARP — используйте Sing-box/VLESS либо AmneziaWG со своим сервером."
		advice.Alternatives = []string{"sing-box", "amneziawg", "nfqws2"}
	} else if strings.Contains(lower, "context deadline exceeded") || strings.Contains(lower, "context canceled") {
		advice.Code = "DATAPLANE_OPERATION_CANCELLED"
		advice.Title = "Применение остановлено по времени"
		advice.Message = "Операция была отменена или превысила безопасное время ожидания. RAZVILKA запустила rollback в отдельном ограниченном окне; черновик сохранён."
		advice.Resolution = "Проверьте состояние rollback в диагностике. Если сеть работает, устраните медленный или недоступный обход и повторите Apply; не запускайте вторую операцию одновременно."
	}
	return advice
}

func (a *App) buildDataplanePlan(cfg config.Config, options []routecatalog.Option) (dataplane.Plan, error) {
	return a.buildDataplanePlanForScope(cfg, options, changeScopeAll, "")
}

type changeScope string

const (
	changeScopeAll     changeScope = "all"
	changeScopeRouting changeScope = "routing"
	changeScopeEngine  changeScope = "engine"
)

func changeScopeFromRequest(r *http.Request) (changeScope, string, error) {
	raw := strings.TrimSpace(strings.ToLower(r.URL.Query().Get("scope")))
	if raw == "" {
		raw = string(changeScopeAll)
	}
	scope := changeScope(raw)
	if scope != changeScopeAll && scope != changeScopeRouting && scope != changeScopeEngine {
		return "", "", fmt.Errorf("unknown change scope %q", raw)
	}
	engineID := strings.TrimSpace(strings.ToLower(r.URL.Query().Get("engine")))
	if scope == changeScopeEngine && engineID == "" {
		return "", "", errors.New("engine scope requires engine id")
	}
	return scope, engineID, nil
}

func (a *App) buildDataplanePlanForScope(cfg config.Config, options []routecatalog.Option, scope changeScope, engineID string) (dataplane.Plan, error) {
	routes := make([]dataplane.Route, 0)
	for _, service := range a.catalogSnapshot().Services {
		state := cfg.Services[service.ID]
		if !state.Enabled {
			continue
		}
		selected := selectedRoute(state)
		resolved := selected
		if selected == "auto" {
			resolved = a.resolveAutoWithOptions(service, cfg.EngineOrder, options)
		}
		applied := cfg.AppliedServices[service.ID]
		appliedRoute := ""
		if applied.Enabled {
			appliedRoute = selectedRoute(applied)
		}
		routes = append(routes, dataplane.Route{
			ServiceID: service.ID, ServiceName: service.Name, Selected: selected, Resolved: resolved,
			Domains: service.Domains, CIDRs: service.CIDRs, SourceRefs: service.SourceRefs, Sources: append([]string(nil), state.Sources...), ProbeURL: service.ProbeURL, AppliedRoute: appliedRoute,
		})
	}
	engines := make([]dataplane.Engine, 0, len(options))
	for _, option := range options {
		if option.ID == "auto" || option.ID == "direct" {
			continue
		}
		engines = append(engines, dataplane.Engine{ID: option.ID, Installed: option.Installed, Configured: option.Selectable, Running: option.Running, Activatable: a.Dataplane != nil && a.Dataplane.Capable(option.ID)})
	}
	resourceConflicts := []dataplane.ResourceConflict{}
	if a.EngineLab != nil {
		adapterSet := map[string]bool{}
		for _, route := range routes {
			if adapter := dataplane.AdapterID(route.Resolved); adapter != "" && adapter != "direct" {
				adapterSet[adapter] = true
			}
		}
		adapters := make([]string, 0, len(adapterSet))
		for adapter := range adapterSet {
			adapters = append(adapters, adapter)
		}
		sort.Strings(adapters)
		for _, conflict := range a.EngineLab.Inspect().ApplyConflicts(adapters) {
			resourceConflicts = append(resourceConflicts, dataplane.ResourceConflict{Kind: conflict.Kind, Value: conflict.Value, Engines: conflict.Engines, SystemUse: conflict.SystemUse})
		}
	}
	drafts := a.stagedEngineConfigRefs()
	switch scope {
	case changeScopeRouting:
		used := map[string]bool{}
		for _, route := range routes {
			if adapter := dataplane.AdapterID(route.Resolved); adapter != "" && adapter != "direct" {
				used[adapter] = true
			}
		}
		drafts = filterEngineConfigRefs(drafts, func(id string) bool { return used[id] })
	case changeScopeEngine:
		drafts = filterEngineConfigRefs(drafts, func(id string) bool { return id == engineID })
	}
	return dataplane.Build(dataplane.Input{Revision: cfg.Revision, SafeMode: cfg.SafeMode, Routes: routes, Engines: engines, EngineConfigDrafts: drafts, ResourceConflicts: resourceConflicts, Host: dataplane.DiscoverHost()})
}

func filterEngineConfigRefs(refs []string, keep func(string) bool) []string {
	filtered := make([]string, 0, len(refs))
	for _, ref := range refs {
		engineID := strings.SplitN(ref, "/", 2)[0]
		if keep(engineID) {
			filtered = append(filtered, ref)
		}
	}
	return filtered
}

func (a *App) stagedEngineConfigRefs() []string {
	if a.EngineConfigs == nil {
		return nil
	}
	var refs []string
	for _, engineView := range a.EngineConfigs.List() {
		for _, fileView := range engineView.Files {
			if fileView.Staged {
				refs = append(refs, engineView.ID+"/"+fileView.ID)
			}
		}
	}
	sort.Strings(refs)
	return refs
}

func (a *App) pendingChanges() bool {
	return a.Store.Dirty() || len(a.stagedEngineConfigRefs()) > 0
}

func (a *App) scopePendingChanges(scope changeScope, engineID string) bool {
	switch scope {
	case changeScopeRouting:
		return a.Store.Dirty()
	case changeScopeEngine:
		return len(filterEngineConfigRefs(a.stagedEngineConfigRefs(), func(id string) bool { return id == engineID })) > 0
	default:
		return a.pendingChanges()
	}
}

func (a *App) discard(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	scope, engineID, scopeErr := changeScopeFromRequest(r)
	if scopeErr != nil {
		http.Error(w, scopeErr.Error(), http.StatusBadRequest)
		return
	}
	if scope != changeScopeEngine {
		if err := a.Store.DiscardDraft(); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
	discarded := 0
	if scope == changeScopeRouting {
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "scope": scope, "pending_changes": a.pendingChanges(), "scope_pending_changes": false, "discarded_engine_drafts": 0})
		return
	}
	if a.EngineConfigs != nil {
		for _, ref := range a.stagedEngineConfigRefs() {
			parts := strings.SplitN(ref, "/", 2)
			if len(parts) != 2 || (scope == changeScopeEngine && parts[0] != engineID) {
				continue
			}
			if a.EngineConfigs.Discard(parts[0], parts[1]) == nil {
				discarded++
			}
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "scope": scope, "pending_changes": a.pendingChanges(), "scope_pending_changes": a.scopePendingChanges(scope, engineID), "discarded_engine_drafts": discarded})
}

func (a *App) systemInfo(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	writeJSON(w, http.StatusOK, systemprobe.Probe())
}

func (a *App) metrics(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	if a.Stats == nil {
		http.Error(w, "router metrics are disabled", http.StatusServiceUnavailable)
		return
	}
	limit := 120
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 1 || parsed > routerstats.DefaultHistoryLimit {
			http.Error(w, "limit must be between 1 and 720", http.StatusBadRequest)
			return
		}
		limit = parsed
	}
	latest := a.Stats.Latest()
	history := a.Stats.History(limit)
	if r.URL.Query().Get("period") == "week" {
		history = a.Stats.PersistentHistory(limit)
	}
	trafficNow := latest.Timestamp
	if trafficNow.IsZero() {
		trafficNow = time.Now().UTC()
	}
	trafficHistory := routerstats.MergeHistory(a.Stats.PersistentHistory(0), a.Stats.History(0))
	persistent, persistError := a.Stats.PersistenceStatus()
	writeJSON(w, http.StatusOK, map[string]any{
		"latest":             latest,
		"history":            history,
		"capacity":           routerstats.Assess(latest),
		"traffic_periods":    routerstats.TrafficPeriods(trafficHistory, trafficNow),
		"history_persistent": persistent,
		"history_error":      persistError,
	})
}

func (a *App) safeModeSetting(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		methodNotAllowed(w)
		return
	}
	var in struct {
		Enabled bool `json:"enabled"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&in); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	if err := a.Store.SetSafeMode(in.Enabled); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	cfg := a.Store.Get()
	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true, "safe_mode": cfg.SafeMode, "revision": cfg.Revision,
		"note": "Safe Mode controls future live writes. Existing committed dataplane state is unchanged until the next Apply.",
	})
}

func (a *App) domainDiagnostic(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	query, address, err := normalizeDiagnosticTarget(r.URL.Query().Get("q"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	cfg := a.Store.Get()
	options := a.routeOptionsSnapshot()
	matches := make([]map[string]any, 0)
	for _, service := range a.catalogSnapshot().Services {
		matched, rule, specificity := matchServiceTarget(service, query, address)
		if !matched {
			continue
		}
		state := cfg.Services[service.ID]
		selected := selectedRoute(state)
		resolved := selected
		if selected == "auto" {
			resolved = a.resolveAutoWithOptions(service, cfg.EngineOrder, options)
		}
		applied := cfg.AppliedServices[service.ID]
		matches = append(matches, map[string]any{
			"service_id": service.ID, "service_name": service.Name, "category": service.Category,
			"matched_rule": rule, "specificity": specificity, "enabled": state.Enabled,
			"selected_route": selected, "resolved_route": resolved,
			"applied_enabled": applied.Enabled, "applied_route": selectedRoute(applied),
			"source_refs": service.SourceRefs, "custom": strings.HasPrefix(service.ID, "custom-"),
		})
	}
	sort.Slice(matches, func(i, j int) bool {
		left, _ := matches[i]["specificity"].(int)
		right, _ := matches[j]["specificity"].(int)
		if left == right {
			return matches[i]["service_id"].(string) < matches[j]["service_id"].(string)
		}
		return left > right
	})
	writeJSON(w, http.StatusOK, map[string]any{
		"query": r.URL.Query().Get("q"), "normalized": query, "is_ip": address.IsValid(), "matches": matches,
		"conflict": len(matches) > 1, "winner_candidate": firstMatch(matches), "live_route_confirmed": false,
		"note": "This is a catalog and desired-state explanation. A live route is confirmed only by isolated route evidence or a dataplane adapter.",
	})
}

type diagnosticSource struct {
	ID        string `json:"id"`
	Kind      string `json:"kind"`
	Ready     bool   `json:"ready"`
	Entries   int    `json:"entries"`
	LastError string `json:"last_error,omitempty"`
}

type diagnosticDataplane struct {
	Exists            bool           `json:"exists"`
	PlanID            string         `json:"plan_id,omitempty"`
	Digest            string         `json:"digest,omitempty"`
	State             string         `json:"state,omitempty"`
	Adapters          []string       `json:"adapters,omitempty"`
	BlockerCodes      []string       `json:"blocker_codes,omitempty"`
	WarningCodes      []string       `json:"warning_codes,omitempty"`
	RequiredEvidence  evidence.Level `json:"required_evidence"`
	ObservedEvidence  evidence.Level `json:"observed_evidence"`
	CommittedPlanID   string         `json:"committed_plan_id,omitempty"`
	CommittedState    string         `json:"committed_state,omitempty"`
	CommittedEvidence evidence.Level `json:"committed_evidence"`
}

type diagnosticDocument struct {
	Kind             string               `json:"kind"`
	Schema           int                  `json:"schema"`
	AppVersion       string               `json:"app_version"`
	GeneratedAt      string               `json:"generated_at"`
	System           systemprobe.Snapshot `json:"system"`
	Engines          []engine.Status      `json:"engines"`
	Sources          []diagnosticSource   `json:"sources"`
	Dataplane        diagnosticDataplane  `json:"dataplane"`
	SafeMode         bool                 `json:"safe_mode"`
	Revision         uint64               `json:"revision"`
	AppliedRevision  uint64               `json:"applied_revision"`
	EnabledServices  int                  `json:"enabled_services"`
	AppliedServices  int                  `json:"applied_services"`
	SelectedRoutes   map[string]int       `json:"selected_route_counts"`
	AppliedRoutes    map[string]int       `json:"applied_route_counts"`
	HighestEvidence  evidence.Level       `json:"highest_evidence_level"`
	EvidenceCounts   map[string]int       `json:"evidence_counts"`
	PrivacyOmissions []string             `json:"privacy_omissions"`
	Digest           string               `json:"digest"`
}

func (a *App) diagnosticReport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	cfg := a.Store.Get()
	system := systemprobe.Probe()
	// Hostnames can identify a household or device. Interface names and
	// capability flags are sufficient for compatibility analysis.
	system.Hostname = ""
	document := diagnosticDocument{
		Kind: "razvilka-diagnostic", Schema: 2, AppVersion: Version,
		GeneratedAt: time.Now().UTC().Format(time.RFC3339), System: system,
		Engines: (engine.Detector{}).All(), SafeMode: cfg.SafeMode,
		Revision: cfg.Revision, AppliedRevision: cfg.AppliedRevision,
		Dataplane:      diagnosticDataplane{RequiredEvidence: evidence.None, ObservedEvidence: evidence.None, CommittedEvidence: evidence.None},
		SelectedRoutes: map[string]int{}, AppliedRoutes: map[string]int{}, HighestEvidence: evidence.None, EvidenceCounts: map[string]int{},
		PrivacyOmissions: []string{"engine configuration and credentials", "recovery key and UI sessions", "client IP/CIDR scopes", "connection and browsing history", "probe URLs and raw probe responses", "router hostname and public IP addresses"},
	}
	for _, state := range cfg.Services {
		if state.Enabled {
			document.EnabledServices++
			document.SelectedRoutes[selectedRoute(state)]++
		}
	}
	for _, state := range cfg.AppliedServices {
		if state.Enabled {
			document.AppliedServices++
			document.AppliedRoutes[selectedRoute(state)]++
		}
	}
	for _, proof := range a.serviceEvidenceSnapshot(cfg, a.catalogSnapshot().Services) {
		document.EvidenceCounts[string(proof.Level)]++
		document.HighestEvidence = evidence.Stronger(document.HighestEvidence, proof.Level)
	}
	if a.Sources != nil {
		for _, source := range a.Sources.List() {
			document.Sources = append(document.Sources, diagnosticSource{ID: source.ID, Kind: source.Kind, Ready: source.Ready, Entries: source.Entries, LastError: source.LastError})
		}
	}
	if a.Dataplane != nil {
		if plan, exists, err := a.Dataplane.Latest(); err == nil {
			document.Dataplane.Exists = exists
			if exists {
				document.Dataplane.PlanID, document.Dataplane.Digest, document.Dataplane.State = plan.PlanID, plan.Digest, plan.State
				document.Dataplane.RequiredEvidence, document.Dataplane.ObservedEvidence = plan.RequiredEvidence, plan.ObservedEvidence
				document.Dataplane.Adapters = append([]string(nil), plan.Adapters...)
				for _, blocker := range plan.Blockers {
					document.Dataplane.BlockerCodes = append(document.Dataplane.BlockerCodes, blocker.Code)
				}
				for _, warning := range plan.Warnings {
					document.Dataplane.WarningCodes = append(document.Dataplane.WarningCodes, warning.Code)
				}
			}
		}
		if committed, exists, err := a.Dataplane.Committed(); err == nil && exists {
			document.Dataplane.CommittedPlanID = committed.PlanID
			document.Dataplane.CommittedState = committed.State
			document.Dataplane.CommittedEvidence = committed.ObservedEvidence
		}
	}
	document.Digest = ""
	data, err := json.Marshal(document)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	digest := sha256.Sum256(data)
	document.Digest = hex.EncodeToString(digest[:])
	w.Header().Set("Content-Disposition", `attachment; filename="razvilka-diagnostic.json"`)
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, document)
}

func normalizeDiagnosticTarget(raw string) (string, netip.Addr, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" || len(raw) > 2048 {
		return "", netip.Addr{}, errors.New("enter a domain, IP address, or HTTPS URL")
	}
	if strings.Contains(raw, "://") {
		parsed, err := url.Parse(raw)
		if err != nil || parsed.Hostname() == "" {
			return "", netip.Addr{}, errors.New("invalid URL")
		}
		raw = parsed.Hostname()
	}
	raw = strings.ToLower(strings.TrimSuffix(strings.Trim(raw, "[]"), "."))
	if address, err := netip.ParseAddr(raw); err == nil {
		return address.String(), address.Unmap(), nil
	}
	if len(raw) > 253 || !strings.Contains(raw, ".") || strings.ContainsAny(raw, " /\\@") {
		return "", netip.Addr{}, errors.New("invalid domain")
	}
	for _, label := range strings.Split(raw, ".") {
		if label == "" || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return "", netip.Addr{}, errors.New("invalid domain")
		}
		for _, char := range label {
			if char >= 'a' && char <= 'z' || char >= '0' && char <= '9' || char == '-' {
				continue
			}
			return "", netip.Addr{}, errors.New("invalid domain")
		}
	}
	return raw, netip.Addr{}, nil
}

func matchServiceTarget(service catalog.Service, query string, address netip.Addr) (bool, string, int) {
	if address.IsValid() {
		for _, raw := range service.CIDRs {
			prefix, err := netip.ParsePrefix(raw)
			if err == nil && prefix.Contains(address) {
				return true, raw, prefix.Bits()
			}
		}
		return false, "", 0
	}
	best := ""
	for _, domain := range service.Domains {
		domain = strings.ToLower(strings.TrimSuffix(domain, "."))
		if query == domain || strings.HasSuffix(query, "."+domain) {
			if len(domain) > len(best) {
				best = domain
			}
		}
	}
	return best != "", best, len(best)
}

func firstMatch(matches []map[string]any) any {
	if len(matches) == 0 {
		return nil
	}
	return matches[0]
}

func (a *App) configExport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	cfg := a.Store.Get()
	writeJSON(w, http.StatusOK, map[string]any{"schema": 1, "version": Version, "config": cfg, "catalog_services": len(a.catalogSnapshot().Services)})
}

type profilePreviewResult struct {
	Valid                        bool                       `json:"valid"`
	Name                         string                     `json:"name"`
	Author                       string                     `json:"author,omitempty"`
	Digest                       string                     `json:"digest"`
	FromVersion                  string                     `json:"from_version"`
	ServiceChanges               []map[string]any           `json:"service_changes"`
	CustomAdded                  int                        `json:"custom_added"`
	CustomUpdated                int                        `json:"custom_updated"`
	EngineFiles                  []engineconfig.Validation  `json:"engine_files"`
	Warnings                     []string                   `json:"warnings"`
	SensitiveOmitted             []profileexchange.Omission `json:"sensitive_omitted,omitempty"`
	RequiresCustomUpdateApproval bool                       `json:"requires_custom_update_approval"`
	DraftOnly                    bool                       `json:"draft_only"`
}

func (a *App) profileExport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	bundle := profileexchange.New(Version, r.URL.Query().Get("name"), r.URL.Query().Get("description"), r.URL.Query().Get("author"))
	cfg := a.Store.Get()
	for id, state := range cfg.Services {
		bundle.Services[id] = state
	}
	if a.CustomServices != nil {
		bundle.CustomServices = a.CustomServices.List()
	}
	if a.EngineConfigs != nil {
		for _, engineView := range a.EngineConfigs.List() {
			for _, fileView := range engineView.Files {
				if fileView.Sensitive {
					if fileView.Exists || fileView.Staged {
						bundle.SensitiveOmitted = append(bundle.SensitiveOmitted, profileexchange.Omission{EngineID: engineView.ID, FileID: fileView.ID, Reason: "secret file is never exported"})
					}
					continue
				}
				content, err := a.EngineConfigs.Read(engineView.ID, fileView.ID)
				if err != nil || content.Source == "missing" || content.Content == "" {
					continue
				}
				if looksSensitive(content.Content) {
					bundle.SensitiveOmitted = append(bundle.SensitiveOmitted, profileexchange.Omission{EngineID: engineView.ID, FileID: fileView.ID, Reason: "possible credential marker detected"})
					continue
				}
				bundle.EngineFiles = append(bundle.EngineFiles, profileexchange.EngineFile{EngineID: engineView.ID, FileID: fileView.ID, Content: content.Content, SHA256: profileexchange.Sum([]byte(content.Content))})
			}
		}
	}
	if err := profileexchange.Seal(&bundle); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := profileexchange.Validate(bundle); err != nil {
		http.Error(w, err.Error(), http.StatusRequestEntityTooLarge)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Disposition", `attachment; filename="razvilka-profile.json"`)
	writeJSON(w, http.StatusOK, bundle)
}

func (a *App) profilePreview(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	bundle, err := decodeProfile(w, r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	preview, err := a.previewProfile(bundle)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, http.StatusOK, preview)
}

func (a *App) profileImport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	if a.CustomServices == nil || a.EngineConfigs == nil {
		http.Error(w, "profile import managers are disabled", http.StatusServiceUnavailable)
		return
	}
	var request struct {
		Bundle             profileexchange.Bundle `json:"bundle"`
		AllowCustomUpdates bool                   `json:"allow_custom_updates"`
	}
	reader := http.MaxBytesReader(w, r.Body, profileexchange.MaxBundleBytes+(1<<20))
	if err := json.NewDecoder(reader).Decode(&request); err != nil {
		http.Error(w, "invalid profile import json", http.StatusBadRequest)
		return
	}
	preview, err := a.previewProfile(request.Bundle)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if preview.RequiresCustomUpdateApproval && !request.AllowCustomUpdates {
		writeJSON(w, http.StatusConflict, map[string]any{"error": "profile updates existing custom services; preview and confirm first", "preview": preview})
		return
	}
	reserved := a.reservedServiceIDs()
	previousCustom := a.CustomServices.List()
	previousDraft := a.Store.Get().Services
	if _, err := a.CustomServices.Merge(request.Bundle.CustomServices, reserved, request.AllowCustomUpdates); err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	rollback := func(cause error) {
		customErr := a.CustomServices.ReplaceAll(previousCustom, reserved)
		configErr := a.Store.ReplaceDraft(previousDraft)
		if customErr != nil || configErr != nil {
			http.Error(w, fmt.Sprintf("profile import failed: %v; rollback custom=%v config=%v", cause, customErr, configErr), http.StatusInternalServerError)
			return
		}
		http.Error(w, cause.Error(), http.StatusInternalServerError)
	}
	if err := a.Store.MergeDraft(request.Bundle.Services); err != nil {
		rollback(err)
		return
	}
	items := make([]engineconfig.StageItem, 0, len(request.Bundle.EngineFiles))
	for _, file := range request.Bundle.EngineFiles {
		items = append(items, engineconfig.StageItem{EngineID: file.EngineID, FileID: file.FileID, Content: file.Content})
	}
	if _, err := a.EngineConfigs.StagePublic(items); err != nil {
		rollback(err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true, "draft_only": true, "profile": request.Bundle.Name, "digest": request.Bundle.Digest,
		"services_staged": len(request.Bundle.Services), "custom_services_staged": len(request.Bundle.CustomServices), "engine_files_staged": len(request.Bundle.EngineFiles),
		"note": "Profile was imported into draft only. Validate engine drafts and review the route plan before Apply.",
	})
}

type privateBackupPreviewResult struct {
	Valid           bool                      `json:"valid"`
	CreatedAt       string                    `json:"created_at"`
	FromVersion     string                    `json:"from_version"`
	Digest          string                    `json:"digest"`
	Services        int                       `json:"services"`
	CustomServices  int                       `json:"custom_services"`
	EngineFiles     []engineconfig.Validation `json:"engine_files"`
	SensitiveFiles  int                       `json:"sensitive_files"`
	Devices         int                       `json:"devices"`
	Warnings        []string                  `json:"warnings"`
	DraftOnly       bool                      `json:"draft_only"`
	RestoresAccount bool                      `json:"restores_account"`
}

func (a *App) privateBackupExport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	if a.EngineConfigs == nil || a.CustomServices == nil {
		http.Error(w, "private backup managers are disabled", http.StatusServiceUnavailable)
		return
	}
	var request struct {
		Password string `json:"password"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&request); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	payload := privatebackup.NewPayload(Version)
	configuration := a.Store.Get()
	payload.Services = configuration.Services
	payload.EngineOrder = append([]string(nil), configuration.EngineOrder...)
	payload.CustomServices = a.CustomServices.List()
	if a.Devices != nil {
		payload.Devices = a.Devices.Known()
	}
	for _, engineView := range a.EngineConfigs.List() {
		for _, fileView := range engineView.Files {
			content, err := a.EngineConfigs.ReadExpert(engineView.ID, fileView.ID)
			if err != nil || content.Source == "missing" || content.Content == "" {
				continue
			}
			payload.EngineFiles = append(payload.EngineFiles, privatebackup.EngineFile{
				EngineID: engineView.ID, FileID: fileView.ID, Content: content.Content,
				SHA256: privatebackup.Sum([]byte(content.Content)), Sensitive: fileView.Sensitive || looksSensitive(content.Content),
			})
		}
	}
	if err := privatebackup.Seal(&payload); err != nil {
		http.Error(w, err.Error(), http.StatusRequestEntityTooLarge)
		return
	}
	envelope, err := privatebackup.Encrypt(payload, request.Password)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Disposition", `attachment; filename="razvilka-private-backup.json"`)
	writeJSON(w, http.StatusOK, envelope)
}

func (a *App) privateBackupPreview(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	payload, err := decodePrivateBackup(w, r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	preview, err := a.previewPrivateBackup(payload)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, http.StatusOK, preview)
}

func (a *App) privateBackupImport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	if a.CustomServices == nil || a.EngineConfigs == nil {
		http.Error(w, "private backup managers are disabled", http.StatusServiceUnavailable)
		return
	}
	var request struct {
		Envelope privatebackup.Envelope `json:"envelope"`
		Password string                 `json:"password"`
		Confirm  string                 `json:"confirm"`
	}
	reader := http.MaxBytesReader(w, r.Body, privatebackup.MaxEnvelope*2)
	if err := json.NewDecoder(reader).Decode(&request); err != nil {
		http.Error(w, "invalid private backup json", http.StatusBadRequest)
		return
	}
	if request.Confirm != "IMPORT_PRIVATE_BACKUP" {
		http.Error(w, "explicit private backup confirmation is required", http.StatusBadRequest)
		return
	}
	payload, err := privatebackup.Decrypt(request.Envelope, request.Password)
	request.Password = ""
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if _, err := a.previewPrivateBackup(payload); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	reserved := a.reservedServiceIDs()
	previousCustom := a.CustomServices.List()
	previousDraft := a.Store.Get().Services
	var previousDevices []devices.Device
	if a.Devices != nil {
		previousDevices = a.Devices.Known()
	}
	rollback := func(cause error) {
		customErr := a.CustomServices.ReplaceAll(previousCustom, reserved)
		configErr := a.Store.ReplaceDraft(previousDraft)
		var deviceErr error
		if a.Devices != nil {
			deviceErr = a.Devices.ReplaceAll(previousDevices)
		}
		if customErr != nil || configErr != nil || deviceErr != nil {
			http.Error(w, fmt.Sprintf("private backup import failed: %v; rollback custom=%v config=%v devices=%v", cause, customErr, configErr, deviceErr), http.StatusInternalServerError)
			return
		}
		http.Error(w, cause.Error(), http.StatusInternalServerError)
	}
	if _, err := a.CustomServices.Merge(payload.CustomServices, reserved, true); err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	if a.Devices != nil {
		if err := a.Devices.MergeMetadata(payload.Devices); err != nil {
			rollback(err)
			return
		}
	}
	if err := a.Store.ReplaceDraft(payload.Services); err != nil {
		rollback(err)
		return
	}
	items := make([]engineconfig.StageItem, 0, len(payload.EngineFiles))
	for _, file := range payload.EngineFiles {
		items = append(items, engineconfig.StageItem{EngineID: file.EngineID, FileID: file.FileID, Content: file.Content})
	}
	if _, err := a.EngineConfigs.StagePrivate(items); err != nil {
		rollback(err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true, "draft_only": true, "digest": payload.Digest,
		"services_staged": len(payload.Services), "custom_services_merged": len(payload.CustomServices),
		"engine_files_staged": len(payload.EngineFiles), "devices_merged": len(payload.Devices),
		"note": "Private data was decrypted in memory and imported only into draft. UI credentials, recovery key and live dataplane were not changed.",
	})
}

func decodePrivateBackup(w http.ResponseWriter, r *http.Request) (privatebackup.Payload, error) {
	var request struct {
		Envelope privatebackup.Envelope `json:"envelope"`
		Password string                 `json:"password"`
	}
	reader := http.MaxBytesReader(w, r.Body, privatebackup.MaxEnvelope*2)
	if err := json.NewDecoder(reader).Decode(&request); err != nil {
		return privatebackup.Payload{}, errors.New("invalid private backup json")
	}
	payload, err := privatebackup.Decrypt(request.Envelope, request.Password)
	request.Password = ""
	return payload, err
}

func (a *App) previewPrivateBackup(payload privatebackup.Payload) (privateBackupPreviewResult, error) {
	preview := privateBackupPreviewResult{
		CreatedAt: payload.CreatedAt, FromVersion: payload.AppVersion, Digest: payload.Digest,
		Services: len(payload.Services), CustomServices: len(payload.CustomServices), Devices: len(payload.Devices),
		Warnings:  []string{"UI login, recovery key and live dataplane are intentionally not restored", "engine_order is preserved in the archive but remains unchanged until schema-aware ordering is available"},
		DraftOnly: true, RestoresAccount: false,
	}
	if err := privatebackup.Validate(payload); err != nil {
		return preview, err
	}
	known := map[string]bool{}
	for _, service := range a.catalogSnapshot().Services {
		known[service.ID] = true
	}
	for _, service := range payload.CustomServices {
		if known[service.ID] && !strings.HasPrefix(service.ID, "custom-") {
			return preview, fmt.Errorf("private backup custom service %q conflicts with the built-in catalog", service.ID)
		}
		known[service.ID] = true
	}
	for id := range payload.Services {
		if !known[id] {
			return preview, fmt.Errorf("private backup references unknown service %q", id)
		}
	}
	for _, file := range payload.EngineFiles {
		validation := engineconfig.ValidatePrivateContent(file.EngineID, file.FileID, file.Content)
		preview.EngineFiles = append(preview.EngineFiles, validation)
		if file.Sensitive {
			preview.SensitiveFiles++
		}
		if !validation.OK {
			return preview, fmt.Errorf("engine file %s/%s: %s", file.EngineID, file.FileID, validation.Output)
		}
	}
	preview.Valid = true
	return preview, nil
}

func decodeProfile(w http.ResponseWriter, r *http.Request) (profileexchange.Bundle, error) {
	var bundle profileexchange.Bundle
	reader := http.MaxBytesReader(w, r.Body, profileexchange.MaxBundleBytes+(64<<10))
	if err := json.NewDecoder(reader).Decode(&bundle); err != nil {
		return bundle, errors.New("invalid profile json")
	}
	return bundle, nil
}

func (a *App) previewProfile(bundle profileexchange.Bundle) (profilePreviewResult, error) {
	preview := profilePreviewResult{
		Name: bundle.Name, Author: bundle.Author, Digest: bundle.Digest, FromVersion: bundle.AppVersion,
		SensitiveOmitted: bundle.SensitiveOmitted, DraftOnly: true,
	}
	if err := profileexchange.Validate(bundle); err != nil {
		return preview, err
	}
	known := map[string]bool{}
	for _, service := range a.catalogSnapshot().Services {
		known[service.ID] = true
	}
	for _, service := range bundle.CustomServices {
		known[service.ID] = true
	}
	current := a.Store.Get().Services
	for id, incoming := range bundle.Services {
		if !known[id] {
			return preview, fmt.Errorf("profile references unknown service %q", id)
		}
		before, existed := current[id]
		action := "unchanged"
		if !existed {
			action = "add"
		} else if before.Enabled != incoming.Enabled || selectedRoute(before) != selectedRoute(incoming) {
			action = "change"
		}
		preview.ServiceChanges = append(preview.ServiceChanges, map[string]any{
			"id": id, "action": action, "enabled_before": before.Enabled, "enabled_after": incoming.Enabled,
			"route_before": selectedRoute(before), "route_after": selectedRoute(incoming),
		})
	}
	sort.Slice(preview.ServiceChanges, func(i, j int) bool {
		return preview.ServiceChanges[i]["id"].(string) < preview.ServiceChanges[j]["id"].(string)
	})
	existingCustom := map[string]bool{}
	if a.CustomServices != nil {
		for _, service := range a.CustomServices.List() {
			existingCustom[service.ID] = true
		}
	}
	for _, service := range bundle.CustomServices {
		if existingCustom[service.ID] {
			preview.CustomUpdated++
			preview.RequiresCustomUpdateApproval = true
		} else {
			preview.CustomAdded++
		}
	}
	installed := map[string]bool{}
	for _, status := range (engine.Detector{}).All() {
		installed[status.ID] = status.Installed
	}
	for _, file := range bundle.EngineFiles {
		if !engineconfig.PublicFile(file.EngineID, file.FileID) {
			return preview, fmt.Errorf("engine file %s/%s is not exportable", file.EngineID, file.FileID)
		}
		validation := engineconfig.ValidateContent(file.EngineID, file.FileID, file.Content)
		preview.EngineFiles = append(preview.EngineFiles, validation)
		if !validation.OK {
			return preview, fmt.Errorf("engine file %s/%s: %s", file.EngineID, file.FileID, validation.Output)
		}
		if !installed[file.EngineID] {
			preview.Warnings = append(preview.Warnings, fmt.Sprintf("%s is not installed; its draft can be imported but not applied", file.EngineID))
		}
	}
	if len(bundle.SensitiveOmitted) > 0 {
		preview.Warnings = append(preview.Warnings, fmt.Sprintf("%d sensitive or suspicious engine files were intentionally omitted", len(bundle.SensitiveOmitted)))
	}
	preview.Valid = true
	return preview, nil
}

func (a *App) reservedServiceIDs() map[string]bool {
	reserved := make(map[string]bool, len(a.Catalog.Services))
	for _, builtIn := range a.Catalog.Services {
		reserved[builtIn.ID] = true
	}
	return reserved
}

func looksSensitive(content string) bool {
	markers := []string{"password", "passwd", "private_key", "privatekey", "secret", "authorization", "access_token", "api_token", "uuid"}
	for _, line := range strings.Split(strings.ToLower(content), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		for _, marker := range markers {
			if strings.Contains(line, marker) && strings.ContainsAny(line, "=:") {
				return true
			}
		}
	}
	return false
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
	telemetryStatus := a.Telemetry.Status()
	writeJSON(w, http.StatusOK, map[string]any{
		"connections": a.Telemetry.Snapshot(includeClosed), "live": telemetryStatus.Live,
		"active": active, "closed": closed,
		"producer": telemetryStatus.Producer, "reason": telemetryStatus.Reason,
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
		status := a.Telemetry.Status()
		connections := a.Telemetry.Snapshot(false)
		payload, err := json.Marshal(map[string]any{"connections": connections, "active": len(connections), "live": status.Live, "producer": status.Producer, "reason": status.Reason})
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
	return plannedEngineWithOptions(s, order, routecatalog.Options())
}

func (a *App) resolveAuto(s catalog.Service, order []string) string {
	return a.resolveAutoWithOptions(s, order, a.routeOptionsSnapshot())
}

func (a *App) routeOptionsSnapshot() []routecatalog.Option {
	options := routecatalog.Options()
	for i := range options {
		if options[i].ID == "auto" || options[i].ID == "direct" {
			continue
		}
		a.prepareRouteOption(&options[i])
	}
	return options
}

func (a *App) prepareRouteOption(option *routecatalog.Option) {
	if option == nil {
		return
	}
	// A newly generated WARP profile exists only in RAZVILKA's staging area
	// until the first transactional Apply. The generic engine detector cannot
	// see that file, so without this bridge the user cannot assign a service
	// to WARP and Apply reports ENGINE_DRAFT_UNUSED. Keep Ready false until the
	// tunnel is actually running; this makes the staged route explicitly
	// selectable without allowing AUTO to pick an untested tunnel.
	if option.ID == "warp-wg" && option.Installed && !option.Selectable && a.validStagedWARPProfile() {
		option.Selectable = true
	}
	option.Ready = option.Selectable && a.Dataplane != nil && a.Dataplane.Capable(option.ID)
	if option.ID == "warp-wg" && !option.Running {
		option.Ready = false
	}
}

func (a *App) validStagedWARPProfile() bool {
	if a.EngineConfigs == nil {
		return false
	}
	content, err := a.EngineConfigs.ReadExpert("warp-wg", "main")
	if err != nil || content.Source != "staged" || strings.TrimSpace(content.Content) == "" {
		return false
	}
	return warp.ValidateProfile([]byte(content.Content)) == nil
}

func (a *App) resolveAutoWithOptions(s catalog.Service, order []string, options []routecatalog.Option) string {
	fallback := plannedEngineWithOptions(s, order, options)
	if a.SmartRoute == nil {
		return fallback
	}
	suggested := a.SmartRoute.Suggest(s.ID, fallback)
	if routecatalog.ReadyWithOptions(suggested, options) {
		return suggested
	}
	return fallback
}

func plannedEngineWithOptions(s catalog.Service, order []string, options []routecatalog.Option) string {
	candidates := make([]string, 0, len(s.Strategy)+len(order))
	candidates = append(candidates, s.Strategy...)
	candidates = append(candidates, order...)
	for _, candidate := range candidates {
		if candidate == "auto" {
			continue
		}
		if routecatalog.ReadyWithOptions(candidate, options) {
			return candidate
		}
	}
	return "direct"
}
func stringSlicesEqual(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
func (a *App) hasService(id string) bool {
	for _, s := range a.catalogSnapshot().Services {
		if s.ID == id {
			return true
		}
	}
	return false
}
func (a *App) catalogSnapshot() catalog.Catalog {
	services := make([]catalog.Service, 0, len(a.Catalog.Services))
	services = append(services, a.Catalog.Services...)
	if a.CustomServices != nil {
		services = append(services, a.CustomServices.List()...)
	}
	if a.Sources != nil {
		for index := range services {
			domains, cidrs := a.Sources.EntriesForService(services[index].ID)
			services[index].Domains = mergeUniqueStrings(services[index].Domains, domains)
			services[index].CIDRs = mergeUniqueStrings(services[index].CIDRs, cidrs)
		}
	}
	for index := range services {
		services[index].Probes = append([]catalog.Probe(nil), services[index].Probes...)
	}
	return catalog.Catalog{Services: services}
}
func mergeUniqueStrings(base, extra []string) []string {
	seen := make(map[string]struct{}, len(base)+len(extra))
	out := make([]string, 0, len(base)+len(extra))
	for _, values := range [][]string{base, extra} {
		for _, value := range values {
			value = strings.TrimSpace(value)
			if value == "" {
				continue
			}
			if _, ok := seen[value]; ok {
				continue
			}
			seen[value] = struct{}{}
			out = append(out, value)
		}
	}
	sort.Strings(out)
	return out
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
