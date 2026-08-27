package main

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/ArtixSx/razvilka/internal/app"
	"github.com/ArtixSx/razvilka/internal/auditlog"
	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/community"
	"github.com/ArtixSx/razvilka/internal/components"
	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/conntrack"
	"github.com/ArtixSx/razvilka/internal/customservices"
	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/devices"
	"github.com/ArtixSx/razvilka/internal/dnscontrol"
	"github.com/ArtixSx/razvilka/internal/engine"
	"github.com/ArtixSx/razvilka/internal/engineconfig"
	"github.com/ArtixSx/razvilka/internal/enginelab"
	"github.com/ArtixSx/razvilka/internal/routeprobe"
	"github.com/ArtixSx/razvilka/internal/routerstats"
	"github.com/ArtixSx/razvilka/internal/security"
	"github.com/ArtixSx/razvilka/internal/smartroute"
	"github.com/ArtixSx/razvilka/internal/sources"
	"github.com/ArtixSx/razvilka/internal/strategylab"
	"github.com/ArtixSx/razvilka/internal/systemprobe"
	"github.com/ArtixSx/razvilka/internal/telemetry"
	"github.com/ArtixSx/razvilka/internal/testlab"
	"github.com/ArtixSx/razvilka/internal/updatecheck"
	"github.com/ArtixSx/razvilka/internal/usquediag"
	"github.com/ArtixSx/razvilka/internal/warp"
)

//go:embed web/*
var embedded embed.FS

func main() {
	if handled, code := runCommand(os.Args[1:]); handled {
		os.Exit(code)
	}
	defaultCfg := getenv("RAZVILKA_CONFIG", "/opt/etc/razvilka/config.json")
	defaultCatalog := getenv("RAZVILKA_CATALOG", "/opt/etc/razvilka/service-catalog.json")
	defaultSources := getenv("RAZVILKA_SOURCES", "/opt/etc/razvilka/sources.json")
	defaultCache := getenv("RAZVILKA_CACHE", "/opt/var/cache/razvilka")
	defaultStage := getenv("RAZVILKA_STAGE", "/opt/var/lib/razvilka/staging")
	defaultBackups := getenv("RAZVILKA_BACKUPS", "/opt/var/lib/razvilka/backups")
	defaultToken := getenv("RAZVILKA_TOKEN_FILE", "/opt/etc/razvilka/admin.token")
	defaultCredentials := getenv("RAZVILKA_CREDENTIALS_FILE", "/opt/etc/razvilka/admin.credentials.json")
	defaultCustomServices := getenv("RAZVILKA_CUSTOM_SERVICES", "/opt/etc/razvilka/custom-services.json")
	defaultCommunityCatalog := getenv("RAZVILKA_COMMUNITY_CATALOG", "/opt/etc/razvilka/community-catalog.json")
	defaultWarpState := getenv("RAZVILKA_WARP_STATE", "/opt/var/lib/razvilka/warp")
	defaultSmartRouteState := getenv("RAZVILKA_SMART_ROUTE_STATE", "/opt/var/lib/razvilka/smart-route.json")
	defaultDataplaneState := getenv("RAZVILKA_DATAPLANE_STATE", "/opt/var/lib/razvilka/dataplane")
	defaultDevices := getenv("RAZVILKA_DEVICES", "/opt/etc/razvilka/devices.json")
	defaultMetricsHistory := getenv("RAZVILKA_METRICS_HISTORY", "/opt/var/lib/razvilka/metrics/history.jsonl")
	defaultStrategyLabState := getenv("RAZVILKA_STRATEGY_LAB_STATE", "/opt/var/lib/razvilka/strategy-lab.json")
	defaultAuditLog := getenv("RAZVILKA_AUDIT_LOG", "/opt/var/lib/razvilka/audit/events.jsonl")
	defaultDNSState := getenv("RAZVILKA_DNS_STATE", "/opt/var/lib/razvilka/dns/state.json")
	defaultZ2KRoot := getenv("RAZVILKA_Z2K_ROOT", "/opt/zapret2")
	cfgPath := flag.String("config", defaultCfg, "config path")
	catalogPath := flag.String("catalog", defaultCatalog, "service catalog path")
	sourcesPath := flag.String("sources", defaultSources, "sources registry path")
	cachePath := flag.String("cache", defaultCache, "validated list cache directory")
	stagePath := flag.String("stage", defaultStage, "engine config staging directory")
	backupPath := flag.String("backups", defaultBackups, "engine config backup directory")
	tokenPath := flag.String("token-file", defaultToken, "administrator token path")
	credentialsPath := flag.String("credentials-file", defaultCredentials, "administrator credentials path")
	customServicesPath := flag.String("custom-services", defaultCustomServices, "custom services path")
	communityCatalogPath := flag.String("community-catalog", defaultCommunityCatalog, "allowlisted community catalog path")
	warpStatePath := flag.String("warp-state", defaultWarpState, "WARP generator state directory")
	smartRouteStatePath := flag.String("smart-route-state", defaultSmartRouteState, "Smart Route evidence state path")
	dataplaneStatePath := flag.String("dataplane-state", defaultDataplaneState, "dataplane transaction journal directory")
	devicesPath := flag.String("devices", defaultDevices, "local device names and groups path")
	metricsHistoryPath := flag.String("metrics-history", defaultMetricsHistory, "bounded router metrics history path")
	strategyLabStatePath := flag.String("strategy-lab-state", defaultStrategyLabState, "NFQWS2 Strategy Lab state path")
	auditLogPath := flag.String("audit-log", defaultAuditLog, "bounded control-plane audit journal path")
	dnsStatePath := flag.String("dns-state", defaultDNSState, "DNS profile draft and probe state path")
	z2kRoot := flag.String("z2k-root", defaultZ2KRoot, "read-only z2k migration source root")
	listen := flag.String("listen", "", "listen override, e.g. 192.168.1.1:8787")
	checkOnly := flag.Bool("check", false, "validate config, catalog and sources without changing files or starting the server")
	migrateConfig := flag.Bool("migrate-config", false, "validate inputs and atomically migrate config to the current schema without starting the server")
	healthURL := flag.String("healthcheck", "", "check a running RAZVILKA status URL and exit")
	healthPID := flag.Int("healthcheck-pid", 0, "require the status response to match this process ID")
	healthDataplane := flag.Bool("healthcheck-require-dataplane", false, "require a committed non-direct dataplane to have current runtime recovery evidence")
	showVersion := flag.Bool("version", false, "print version and exit")
	installComponents := flag.Bool("install-components", false, "install or update recommended bypass components and exit")
	deactivateDataplane := flag.Bool("deactivate-dataplane", false, "remove only RAZVILKA-owned runtime routes, interfaces and processes, then exit")
	flag.Parse()

	if *showVersion {
		fmt.Println(app.Version)
		return
	}
	modes := 0
	for _, enabled := range []bool{*checkOnly, *migrateConfig, *healthURL != "", *installComponents, *deactivateDataplane} {
		if enabled {
			modes++
		}
	}
	if modes > 1 {
		log.Fatal("-check, -migrate-config, -healthcheck, -install-components and -deactivate-dataplane are mutually exclusive")
	}
	if *healthPID < 0 {
		log.Fatal("-healthcheck-pid must not be negative")
	}
	if *healthPID != 0 && *healthURL == "" {
		log.Fatal("-healthcheck-pid requires -healthcheck")
	}
	if *healthDataplane && *healthURL == "" {
		log.Fatal("-healthcheck-require-dataplane requires -healthcheck")
	}
	if *healthURL != "" {
		version, err := checkHealth(*healthURL, *healthPID, *healthDataplane)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("healthy: %s\n", version)
		return
	}
	if *installComponents {
		ctx, cancel := context.WithTimeout(context.Background(), 12*time.Minute)
		defer cancel()
		report := components.New().InstallRecommended(ctx)
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(report); err != nil {
			log.Fatal(err)
		}
		if !report.OK {
			os.Exit(3)
		}
		return
	}
	if *deactivateDataplane {
		engineConfigs := engineconfig.New(*stagePath, *backupPath)
		dataplaneManager, err := newDataplaneManager(*dataplaneStatePath, engineConfigs)
		if err != nil {
			log.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		report, deactivateErr := dataplaneManager.Deactivate(ctx)
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(report); err != nil {
			log.Fatal(err)
		}
		if deactivateErr != nil {
			log.Fatal(deactivateErr)
		}
		return
	}
	if *checkOnly || *migrateConfig {
		report, err := preflight(*cfgPath, *catalogPath, *sourcesPath, *communityCatalogPath, *migrateConfig)
		if err != nil {
			log.Fatal(err)
		}
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(report); err != nil {
			log.Fatal(err)
		}
		return
	}

	store, err := config.Load(*cfgPath)
	if err != nil {
		log.Fatal(err)
	}
	gate, _, tokenCreated, err := security.LoadOrCreateToken(*tokenPath)
	if err != nil {
		log.Fatalf("administrator security gate: %v", err)
	}
	if tokenCreated {
		log.Printf("created administrator recovery token at %s", *tokenPath)
	}
	if err := gate.ConfigureCredentials(*credentialsPath); err != nil {
		log.Fatalf("administrator credentials: %v", err)
	}
	cat, err := loadCatalog(*catalogPath)
	if err != nil {
		log.Fatal(err)
	}
	custom, err := customservices.Load(*customServicesPath)
	if err != nil {
		log.Fatalf("custom services: %v", err)
	}
	deviceManager, err := devices.Load(*devicesPath)
	if err != nil {
		log.Fatalf("device registry: %v", err)
	}
	communityCatalog, err := loadCommunityCatalog(*communityCatalogPath)
	if err != nil {
		log.Printf("community catalog disabled: %v", err)
	}
	reg, err := loadSources(*sourcesPath)
	var sm *sources.Manager
	if err != nil {
		log.Printf("sources registry disabled: %v", err)
	} else {
		sm = sources.NewManager(reg, *cachePath, filepath.Join(filepath.Dir(*sourcesPath), "source-state.json"))
	}
	cfg := store.Get()
	addr := cfg.Listen
	if *listen != "" {
		addr = *listen
	}
	sub, err := fs.Sub(embedded, "web")
	if err != nil {
		log.Fatal(err)
	}
	engineConfigs := engineconfig.New(*stagePath, *backupPath)
	dataplaneManager, err := newDataplaneManager(*dataplaneStatePath, engineConfigs)
	if err != nil {
		log.Fatal(err)
	}
	warpManager := warp.New(*warpStatePath, filepath.Join(*backupPath, "warp"), engineConfigs)
	smartRouteManager, err := smartroute.New(*smartRouteStatePath)
	if err != nil {
		log.Fatalf("Smart Route state: %v", err)
	}
	smartRouteManager.Profile = func() string { return systemprobe.DetectWANProfile().ID }
	dnsManager, err := dnscontrol.New(*dnsStatePath)
	if err != nil {
		log.Fatalf("DNS profile state: %v", err)
	}
	strategyLabManager, err := strategylab.New(*strategyLabStatePath)
	if err != nil {
		log.Fatalf("Strategy Lab state: %v", err)
	}
	routeProber := routeprobe.New(engineConfigs)
	routeProber.DataplaneRoot = *dataplaneStatePath
	telemetryStore := telemetry.NewStore()
	statsSampler := routerstats.New(routerstats.Collector{WANDetector: systemprobe.DetectWANInterface})
	statsSampler.Interval = 10 * time.Second
	if err := statsSampler.EnablePersistence(*metricsHistoryPath); err != nil {
		log.Printf("router metrics history disabled: %v", err)
	}
	engineLab := enginelab.New(engineConfigs)
	engineLab.EnablePolicyInspection()
	a := &app.App{Store: store, Catalog: cat, Sources: sm, Telemetry: telemetryStore, EngineConfigs: engineConfigs, EngineLab: engineLab, StrategyLab: strategyLabManager, Components: components.New(), Community: communityCatalog, CustomServices: custom, Dataplane: dataplaneManager, Devices: deviceManager, DNS: dnsManager, Warp: warpManager, USQUE: usquediag.New(), TestLab: testlab.NewRunner(), RouteProber: routeProber, SmartRoute: smartRouteManager, Updates: updatecheck.New(app.Version), Stats: statsSampler, Security: gate, Audit: auditlog.New(*auditLogPath), Start: time.Now(), EffectiveListen: addr, Z2KRoot: *z2kRoot}
	runtimeContext, stopRuntime := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stopRuntime()
	recoveryContext, cancelRecovery := context.WithTimeout(runtimeContext, 2*time.Minute)
	recovery, recoveryErr := dataplaneManager.Recover(recoveryContext)
	cancelRecovery()
	if recoveryErr != nil {
		log.Printf("dataplane boot recovery %s: %v", recovery.State, recoveryErr)
		if safeErr := store.SetSafeMode(true); safeErr != nil {
			log.Printf("enable Recovery Safe Mode: %v", safeErr)
		} else {
			log.Printf("Recovery Safe Mode enabled; live writes require explicit review")
		}
		_ = a.Audit.Append(auditlog.Event{Action: "BOOT_RECOVERY", Path: "dataplane", Outcome: "failed", Actor: "system", RemoteIP: "local"})
	} else if recovery.State == "recovered" {
		log.Printf("dataplane boot recovery completed for %s", recovery.PlanID)
		_ = a.Audit.Append(auditlog.Event{Action: "BOOT_RECOVERY", Path: "dataplane", Outcome: "ok", Actor: "system", RemoteIP: "local"})
	}
	a.StartBackground(runtimeContext)
	statsSampler.Start(runtimeContext)
	connectionCollector := conntrack.New(telemetryStore, store, func() catalog.Catalog {
		services := append([]catalog.Service(nil), cat.Services...)
		services = append(services, custom.List()...)
		return catalog.Catalog{Services: services}
	})
	connectionCollector.Devices = deviceManager
	connectionCollector.LatestPlan = dataplaneManager.Latest
	connectionCollector.WANInterface = func() string { return systemprobe.Probe().WANInterface }
	connectionCollector.Start(runtimeContext)
	log.Println(app.StartupMessage(addr, *cfgPath, *catalogPath))
	srv := &http.Server{Addr: addr, Handler: a.Handler(http.FileServer(http.FS(sub))), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 120 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10}
	serverErrors := make(chan error, 1)
	go func() { serverErrors <- srv.ListenAndServe() }()
	select {
	case serverErr := <-serverErrors:
		if !errors.Is(serverErr, http.ErrServerClosed) {
			log.Fatal(serverErr)
		}
	case <-runtimeContext.Done():
		shutdownContext, cancelShutdown := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancelShutdown()
		if err := srv.Shutdown(shutdownContext); err != nil {
			log.Printf("HTTP shutdown: %v", err)
		}
	}
}

func runCommand(args []string) (bool, int) {
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		return false, 0
	}
	command := strings.ToLower(strings.TrimSpace(args[0]))
	switch command {
	case "version", "v":
		fmt.Println(app.Version)
		return true, 0
	case "status", "s":
		payload := map[string]any{
			"ok": true, "version": app.Version,
			"system": systemprobe.Probe(), "bypasses": engine.Visible((engine.Detector{}).Inventory()),
		}
		return true, writeCommandJSON(payload)
	case "doctor", "diag", "d":
		snapshot := systemprobe.Probe()
		issues := make([]string, 0, 6)
		if !snapshot.OptReady {
			issues = append(issues, "Entware /opt is not ready")
		}
		if !snapshot.Opkg {
			issues = append(issues, "opkg is not available")
		}
		if !snapshot.IPCommand {
			issues = append(issues, "ip command is not available")
		}
		if snapshot.WANInterface == "" {
			issues = append(issues, "WAN interface was not detected")
		}
		payload := map[string]any{"ok": len(issues) == 0, "version": app.Version, "system": snapshot, "issues": issues}
		code := writeCommandJSON(payload)
		if code == 0 && len(issues) > 0 {
			code = 3
		}
		return true, code
	case "components", "bypasses":
		refresh := len(args) == 2 && args[1] == "--refresh"
		if len(args) > 2 || (len(args) == 2 && !refresh) {
			fmt.Fprintln(os.Stderr, "usage: razvilka components [--refresh]")
			return true, 2
		}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		views, err := components.New().List(ctx, refresh)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return true, 3
		}
		return true, writeCommandJSON(views)
	case "component":
		if len(args) < 4 || args[1] != "plan" {
			fmt.Fprintln(os.Stderr, "usage: razvilka component plan <id> <install|update|remove> [--refresh]")
			return true, 2
		}
		refresh := len(args) == 5 && args[4] == "--refresh"
		if len(args) > 5 || (len(args) == 5 && !refresh) {
			fmt.Fprintln(os.Stderr, "usage: razvilka component plan <id> <install|update|remove> [--refresh]")
			return true, 2
		}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		plan, err := components.New().Plan(ctx, args[2], args[3], refresh)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return true, 3
		}
		return true, writeCommandJSON(plan)
	case "help", "h":
		fmt.Println("RAZVILKA commands: status, doctor, components [--refresh], component plan <id> <action>, version")
		return true, 0
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q; run 'razvilka help'\n", args[0])
		return true, 2
	}
}

func writeCommandJSON(value any) int {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(value); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	return 0
}

func newDataplaneManager(stateRoot string, configs *engineconfig.Manager) (*dataplane.Manager, error) {
	manager := dataplane.New(stateRoot)
	nfqws2Adapter := dataplane.NewNFQWS2Adapter()
	nfqws2Adapter.Configs = configs
	if err := manager.Register(nfqws2Adapter); err != nil {
		return nil, fmt.Errorf("register NFQWS2 dataplane adapter: %w", err)
	}
	for _, adapter := range []dataplane.Adapter{
		dataplane.NewWARPWireGuardAdapter(configs, stateRoot),
		dataplane.NewAmneziaWGAdapter(configs, stateRoot),
	} {
		if err := manager.Register(adapter); err != nil {
			return nil, fmt.Errorf("register %s dataplane adapter: %w", adapter.ID(), err)
		}
	}
	for _, engineID := range []string{"usque", "sing-box", "xray"} {
		adapter, err := dataplane.NewProxyTunnelAdapter(engineID, configs, stateRoot)
		if err != nil {
			return nil, fmt.Errorf("configure %s dataplane adapter: %w", engineID, err)
		}
		if err := manager.Register(adapter); err != nil {
			return nil, fmt.Errorf("register %s dataplane adapter: %w", engineID, err)
		}
	}
	return manager, nil
}

type preflightReport struct {
	OK               bool                   `json:"ok"`
	Version          string                 `json:"version"`
	Config           config.MigrationReport `json:"config"`
	CatalogServices  int                    `json:"catalog_services"`
	Sources          int                    `json:"sources"`
	CommunityEntries int                    `json:"community_entries"`
	Migrated         bool                   `json:"migrated"`
}

func preflight(configPath, catalogPath, sourcesPath, communityPath string, migrate bool) (preflightReport, error) {
	_, configReport, err := config.Inspect(configPath)
	if err != nil {
		return preflightReport{}, fmt.Errorf("config preflight: %w", err)
	}
	cat, err := catalog.Load(catalogPath)
	if err != nil {
		return preflightReport{}, fmt.Errorf("catalog preflight: %w", err)
	}
	reg, err := sources.LoadRegistry(sourcesPath)
	if err != nil {
		return preflightReport{}, fmt.Errorf("sources preflight: %w", err)
	}
	communityCatalog, err := community.Load(communityPath)
	if err != nil {
		return preflightReport{}, fmt.Errorf("community catalog preflight: %w", err)
	}
	if migrate {
		configReport, err = config.Migrate(configPath)
		if err != nil {
			return preflightReport{}, fmt.Errorf("config migration: %w", err)
		}
	}
	return preflightReport{OK: true, Version: app.Version, Config: configReport, CatalogServices: len(cat.Services), Sources: len(reg.Sources), CommunityEntries: len(communityCatalog.Search("", nil)), Migrated: migrate && configReport.Changed}, nil
}

func loadCatalog(path string) (catalog.Catalog, error) {
	c, err := catalog.Load(path)
	if err == nil {
		return c, nil
	}
	for _, p := range []string{"configs/service-catalog.json", filepath.Join(filepath.Dir(os.Args[0]), "service-catalog.json")} {
		if c, e := catalog.Load(p); e == nil {
			return c, nil
		}
	}
	return catalog.Catalog{}, err
}
func loadSources(path string) (sources.Registry, error) {
	r, err := sources.LoadRegistry(path)
	if err == nil {
		return r, nil
	}
	for _, p := range []string{"configs/sources.json", filepath.Join(filepath.Dir(os.Args[0]), "sources.json")} {
		if r, e := sources.LoadRegistry(p); e == nil {
			return r, nil
		}
	}
	return sources.Registry{}, err
}

func loadCommunityCatalog(path string) (*community.Manager, error) {
	m, err := community.Load(path)
	if err == nil {
		return m, nil
	}
	for _, candidate := range []string{"configs/community-catalog.json", filepath.Join(filepath.Dir(os.Args[0]), "community-catalog.json")} {
		if fallback, fallbackErr := community.Load(candidate); fallbackErr == nil {
			return fallback, nil
		}
	}
	return nil, err
}

func checkHealth(rawURL string, expectedPID int, requireDataplane bool) (string, error) {
	client := &http.Client{
		Timeout: 4 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		return "", fmt.Errorf("healthcheck request: %w", err)
	}
	req.Header.Set("User-Agent", "RAZVILKA-healthcheck/"+app.Version)
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("healthcheck request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("healthcheck returned HTTP %d", resp.StatusCode)
	}
	var status struct {
		Name              string `json:"name"`
		Version           string `json:"version"`
		ProcessID         int    `json:"process_id"`
		DataplaneState    string `json:"dataplane_state"`
		DataplaneAdapters int    `json:"dataplane_adapters"`
		DataplaneError    string `json:"dataplane_error"`
		LiveActive        bool   `json:"live_active"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&status); err != nil {
		return "", fmt.Errorf("healthcheck response: %w", err)
	}
	if status.Name != "RAZVILKA" || status.Version != app.Version {
		return "", fmt.Errorf("healthcheck identity mismatch: got %q %q", status.Name, status.Version)
	}
	if expectedPID > 0 && status.ProcessID != expectedPID {
		return "", fmt.Errorf("healthcheck process mismatch: got %d, want %d", status.ProcessID, expectedPID)
	}
	if requireDataplane {
		if status.DataplaneError != "" || status.DataplaneState == "journal-error" {
			return "", errors.New("healthcheck dataplane journal is unavailable")
		}
		if status.DataplaneState == "committed" && status.DataplaneAdapters > 0 && !status.LiveActive {
			return "", errors.New("healthcheck committed dataplane has no current runtime evidence")
		}
	}
	return status.Version, nil
}

func getenv(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}
