package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/ArtixSx/razvilka/internal/config"
)

func TestPreflightCheckAndMigrate(t *testing.T) {
	t.Parallel()
	repositoryConfigs := filepath.Join("..", "..", "configs")
	sourceConfig := filepath.Join(repositoryConfigs, "config.example.json")
	catalogPath := filepath.Join(repositoryConfigs, "service-catalog.json")
	sourcesPath := filepath.Join(repositoryConfigs, "sources.json")

	data, err := os.ReadFile(sourceConfig)
	if err != nil {
		t.Fatal(err)
	}
	legacy := bytes.Replace(data, []byte("  \"schema_version\": 1,\n"), nil, 1)
	if bytes.Equal(legacy, data) {
		t.Fatal("schema_version fixture was not removed")
	}
	configPath := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(configPath, legacy, 0o600); err != nil {
		t.Fatal(err)
	}

	checked, err := preflight(configPath, catalogPath, sourcesPath, false)
	if err != nil {
		t.Fatalf("check preflight: %v", err)
	}
	if !checked.OK || checked.Migrated {
		t.Fatalf("check report = %+v", checked)
	}
	if checked.Config.FromSchema != 0 || checked.Config.ToSchema != config.CurrentSchemaVersion {
		t.Fatalf("check schema report = %+v", checked.Config)
	}
	if checked.CatalogServices != 16 || checked.Sources != 8 {
		t.Fatalf("catalog=%d sources=%d", checked.CatalogServices, checked.Sources)
	}
	unchanged, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(unchanged, legacy) {
		t.Fatal("read-only preflight changed the config")
	}

	migrated, err := preflight(configPath, catalogPath, sourcesPath, true)
	if err != nil {
		t.Fatalf("migration preflight: %v", err)
	}
	if !migrated.OK || !migrated.Migrated || migrated.Config.ToSchema != config.CurrentSchemaVersion {
		t.Fatalf("migration report = %+v", migrated)
	}

	second, err := preflight(configPath, catalogPath, sourcesPath, true)
	if err != nil {
		t.Fatalf("second migration preflight: %v", err)
	}
	if second.Migrated || second.Config.Changed {
		t.Fatalf("second migration was not idempotent: %+v", second)
	}
}
