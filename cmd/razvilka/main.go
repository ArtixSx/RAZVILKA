package main

import (
	"embed"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/ArtixSx/razvilka/internal/app"
	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/engineconfig"
	"github.com/ArtixSx/razvilka/internal/security"
	"github.com/ArtixSx/razvilka/internal/sources"
	"github.com/ArtixSx/razvilka/internal/telemetry"
	"github.com/ArtixSx/razvilka/internal/testlab"
)

//go:embed web/*
var embedded embed.FS

func main() {
	defaultCfg := getenv("RAZVILKA_CONFIG", "/opt/etc/razvilka/config.json")
	defaultCatalog := getenv("RAZVILKA_CATALOG", "/opt/etc/razvilka/service-catalog.json")
	defaultSources := getenv("RAZVILKA_SOURCES", "/opt/etc/razvilka/sources.json")
	defaultCache := getenv("RAZVILKA_CACHE", "/opt/var/cache/razvilka")
	defaultStage := getenv("RAZVILKA_STAGE", "/opt/var/lib/razvilka/staging")
	defaultBackups := getenv("RAZVILKA_BACKUPS", "/opt/var/lib/razvilka/backups")
	defaultToken := getenv("RAZVILKA_TOKEN_FILE", "/opt/etc/razvilka/admin.token")
	cfgPath := flag.String("config", defaultCfg, "config path")
	catalogPath := flag.String("catalog", defaultCatalog, "service catalog path")
	sourcesPath := flag.String("sources", defaultSources, "sources registry path")
	cachePath := flag.String("cache", defaultCache, "validated list cache directory")
	stagePath := flag.String("stage", defaultStage, "engine config staging directory")
	backupPath := flag.String("backups", defaultBackups, "engine config backup directory")
	tokenPath := flag.String("token-file", defaultToken, "administrator token path")
	listen := flag.String("listen", "", "listen override, e.g. 192.168.1.1:8787")
	checkOnly := flag.Bool("check", false, "validate config, catalog and sources without changing files or starting the server")
	migrateConfig := flag.Bool("migrate-config", false, "validate inputs and atomically migrate config to the current schema without starting the server")
	healthURL := flag.String("healthcheck", "", "check a running RAZVILKA status URL and exit")
	healthPID := flag.Int("healthcheck-pid", 0, "require the status response to match this process ID")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println(app.Version)
		return
	}
	modes := 0
	for _, enabled := range []bool{*checkOnly, *migrateConfig, *healthURL != ""} {
		if enabled {
			modes++
		}
	}
	if modes > 1 {
		log.Fatal("-check, -migrate-config and -healthcheck are mutually exclusive")
	}
	if *healthPID < 0 {
		log.Fatal("-healthcheck-pid must not be negative")
	}
	if *healthPID != 0 && *healthURL == "" {
		log.Fatal("-healthcheck-pid requires -healthcheck")
	}
	if *healthURL != "" {
		version, err := checkHealth(*healthURL, *healthPID)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("healthy: %s\n", version)
		return
	}
	if *checkOnly || *migrateConfig {
		report, err := preflight(*cfgPath, *catalogPath, *sourcesPath, *migrateConfig)
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
		log.Printf("created administrator token at %s; copy it from the router before changing settings", *tokenPath)
	}
	cat, err := loadCatalog(*catalogPath)
	if err != nil {
		log.Fatal(err)
	}
	reg, err := loadSources(*sourcesPath)
	var sm *sources.Manager
	if err != nil {
		log.Printf("sources registry disabled: %v", err)
	} else {
		sm = sources.NewManager(reg, *cachePath)
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
	a := &app.App{Store: store, Catalog: cat, Sources: sm, Telemetry: telemetry.NewStore(), EngineConfigs: engineconfig.New(*stagePath, *backupPath), TestLab: testlab.NewRunner(), Security: gate, Start: time.Now(), EffectiveListen: addr}
	log.Println(app.StartupMessage(addr, *cfgPath, *catalogPath))
	srv := &http.Server{Addr: addr, Handler: a.Handler(http.FileServer(http.FS(sub))), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 120 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10}
	log.Fatal(srv.ListenAndServe())
}

type preflightReport struct {
	OK              bool                   `json:"ok"`
	Version         string                 `json:"version"`
	Config          config.MigrationReport `json:"config"`
	CatalogServices int                    `json:"catalog_services"`
	Sources         int                    `json:"sources"`
	Migrated        bool                   `json:"migrated"`
}

func preflight(configPath, catalogPath, sourcesPath string, migrate bool) (preflightReport, error) {
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
	if migrate {
		configReport, err = config.Migrate(configPath)
		if err != nil {
			return preflightReport{}, fmt.Errorf("config migration: %w", err)
		}
	}
	return preflightReport{OK: true, Version: app.Version, Config: configReport, CatalogServices: len(cat.Services), Sources: len(reg.Sources), Migrated: migrate && configReport.Changed}, nil
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

func checkHealth(rawURL string, expectedPID int) (string, error) {
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
		Name      string `json:"name"`
		Version   string `json:"version"`
		ProcessID int    `json:"process_id"`
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
	return status.Version, nil
}

func getenv(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}
