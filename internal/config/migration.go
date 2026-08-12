package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"
	"sort"
)

const CurrentSchemaVersion = 1

type MigrationReport struct {
	FromSchema int      `json:"from_schema"`
	ToSchema   int      `json:"to_schema"`
	Changed    bool     `json:"changed"`
	Changes    []string `json:"changes,omitempty"`
}

func Inspect(path string) (Config, MigrationReport, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return Config{}, MigrationReport{}, err
	}
	return InspectBytes(b)
}

func InspectBytes(b []byte) (Config, MigrationReport, error) {
	var cfg Config
	decoder := json.NewDecoder(bytes.NewReader(b))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&cfg); err != nil {
		return Config{}, MigrationReport{}, fmt.Errorf("decode config: %w", err)
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return Config{}, MigrationReport{}, err
	}

	var fields map[string]json.RawMessage
	if err := json.Unmarshal(b, &fields); err != nil {
		return Config{}, MigrationReport{}, fmt.Errorf("inspect config fields: %w", err)
	}
	report := MigrationReport{FromSchema: cfg.SchemaVersion, ToSchema: CurrentSchemaVersion}
	if cfg.SchemaVersion < 0 {
		return Config{}, report, errors.New("schema_version cannot be negative")
	}
	if cfg.SchemaVersion > CurrentSchemaVersion {
		return Config{}, report, fmt.Errorf("config schema_version %d is newer than supported version %d", cfg.SchemaVersion, CurrentSchemaVersion)
	}
	if cfg.SchemaVersion < CurrentSchemaVersion {
		cfg.SchemaVersion = CurrentSchemaVersion
		report.add("schema_version upgraded")
	}
	if cfg.Listen == "" {
		cfg.Listen = ":8787"
		report.add("listen defaulted to :8787")
	}
	if cfg.Services == nil {
		cfg.Services = map[string]ServiceState{}
		report.add("services initialized")
	}
	for id, state := range cfg.Services {
		normalized := normalizeState(state)
		if !reflect.DeepEqual(state, normalized) {
			cfg.Services[id] = normalized
			report.add("service route fields normalized")
		}
	}
	if _, present := fields["applied_services"]; !present || cfg.AppliedServices == nil {
		cfg.AppliedServices = cloneServices(cfg.Services)
		report.add("applied_services initialized from services")
	}
	for id, state := range cfg.AppliedServices {
		normalized := normalizeState(state)
		if !reflect.DeepEqual(state, normalized) {
			cfg.AppliedServices[id] = normalized
			report.add("applied service route fields normalized")
		}
	}
	if len(cfg.EngineOrder) == 0 {
		cfg.EngineOrder = append([]string(nil), Default().EngineOrder...)
		report.add("engine_order initialized")
	}
	if _, present := fields["safe_mode"]; !present {
		cfg.SafeMode = true
		report.add("safe_mode defaulted to true")
	}
	if cfg.AppliedRevision == 0 && len(cfg.AppliedServices) > 0 {
		cfg.AppliedRevision = cfg.Revision
		report.add("applied_revision aligned with revision")
	}
	report.normalize()
	return cfg, report, nil
}

func Migrate(path string) (MigrationReport, error) {
	cfg, report, err := Inspect(path)
	if err != nil {
		return report, err
	}
	if !report.Changed {
		return report, nil
	}
	store := &Store{path: path, cfg: cfg}
	if err := store.Save(); err != nil {
		return report, fmt.Errorf("persist migrated config: %w", err)
	}
	return report, nil
}

func ensureJSONEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); errors.Is(err, io.EOF) {
		return nil
	} else if err != nil {
		return fmt.Errorf("decode trailing config data: %w", err)
	}
	return errors.New("config contains multiple JSON values")
}

func (r *MigrationReport) add(change string) {
	r.Changes = append(r.Changes, change)
}

func (r *MigrationReport) normalize() {
	seen := map[string]bool{}
	unique := r.Changes[:0]
	for _, change := range r.Changes {
		if !seen[change] {
			seen[change] = true
			unique = append(unique, change)
		}
	}
	r.Changes = unique
	sort.Strings(r.Changes)
	r.Changed = len(r.Changes) > 0
}
