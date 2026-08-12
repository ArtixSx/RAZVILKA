package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInspectLegacyConfigIsSafeAndReadOnly(t *testing.T) {
	legacy := []byte(`{"listen":":8787","services":{"youtube":{"enabled":true,"mode":"direct"}},"engine_order":["nfqws2"]}`)
	cfg, report, err := InspectBytes(legacy)
	if err != nil {
		t.Fatal(err)
	}
	if !report.Changed || report.FromSchema != 0 || report.ToSchema != CurrentSchemaVersion {
		t.Fatalf("unexpected report: %+v", report)
	}
	if cfg.SchemaVersion != CurrentSchemaVersion || !cfg.SafeMode {
		t.Fatalf("unsafe migrated config: %+v", cfg)
	}
	state := cfg.Services["youtube"]
	if state.Route != "direct" || state.Mode != "direct" {
		t.Fatalf("route was not normalized: %+v", state)
	}
	if !cfg.AppliedServices["youtube"].Enabled {
		t.Fatal("legacy desired state was not copied to applied state")
	}
}

func TestInspectRejectsFutureUnknownAndTrailingData(t *testing.T) {
	tests := []string{
		`{"schema_version":2,"listen":":8787","services":{},"engine_order":["nfqws2"],"safe_mode":true}`,
		`{"schema_version":1,"listen":":8787","services":{},"engine_order":["nfqws2"],"safe_mode":true,"unexpected":1}`,
		`{"schema_version":1,"listen":":8787","services":{},"engine_order":["nfqws2"],"safe_mode":true} {}`,
	}
	for _, raw := range tests {
		if _, _, err := InspectBytes([]byte(raw)); err == nil {
			t.Fatalf("InspectBytes accepted %s", raw)
		}
	}
}

func TestMigratePersistsAtomicallyAndIsIdempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	legacy := []byte(`{"listen":":8787","services":{},"engine_order":["nfqws2"],"safe_mode":true}`)
	if err := os.WriteFile(path, legacy, 0o600); err != nil {
		t.Fatal(err)
	}
	report, err := Migrate(path)
	if err != nil {
		t.Fatal(err)
	}
	if !report.Changed {
		t.Fatal("legacy migration reported no change")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var persisted Config
	if err := json.Unmarshal(b, &persisted); err != nil {
		t.Fatal(err)
	}
	if persisted.SchemaVersion != CurrentSchemaVersion {
		t.Fatalf("schema_version=%d", persisted.SchemaVersion)
	}
	if strings.Contains(string(b), ".tmp-") {
		t.Fatal("transaction name leaked into config")
	}
	second, err := Migrate(path)
	if err != nil {
		t.Fatal(err)
	}
	if second.Changed {
		t.Fatalf("second migration was not idempotent: %+v", second)
	}
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "config.json" {
		t.Fatalf("unexpected migration files: %+v", entries)
	}
}
