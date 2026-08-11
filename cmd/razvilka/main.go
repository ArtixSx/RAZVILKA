package main

import (
	"embed"
	"flag"
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
	cfgPath := flag.String("config", defaultCfg, "config path")
	catalogPath := flag.String("catalog", defaultCatalog, "service catalog path")
	sourcesPath := flag.String("sources", defaultSources, "sources registry path")
	cachePath := flag.String("cache", defaultCache, "validated list cache directory")
	stagePath := flag.String("stage", defaultStage, "engine config staging directory")
	backupPath := flag.String("backups", defaultBackups, "engine config backup directory")
	listen := flag.String("listen", "", "listen override, e.g. 192.168.1.1:8787")
	flag.Parse()

	store, err := config.Load(*cfgPath)
	if err != nil {
		log.Fatal(err)
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
	a := &app.App{Store: store, Catalog: cat, Sources: sm, Telemetry: telemetry.NewStore(), EngineConfigs: engineconfig.New(*stagePath, *backupPath), TestLab: testlab.NewRunner(), Start: time.Now(), EffectiveListen: addr}
	log.Println(app.StartupMessage(addr, *cfgPath, *catalogPath))
	srv := &http.Server{Addr: addr, Handler: a.Handler(http.FileServer(http.FS(sub))), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 120 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10}
	log.Fatal(srv.ListenAndServe())
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
func getenv(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}
