package updatecheck

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ArtixSx/razvilka/internal/config"
)

// v0.19.3's config.example shape (817783493f0c2784ccc70aa73868cd64e9437634),
// with the same revision/Stop configuration as the genuine public fixture.
const externalOld193SourceConfig = `{"schema_version":1,"listen":":8787","services":{},"applied_services":{},"engine_order":["nfqws2","usque","warp-wg","sing-box"],"safe_mode":true,"revision":1,"service_control":{"stopped":true}}`

func TestExternalBootstrapSourceConfigLegacyFingerprint(t *testing.T) {
	raw := []byte(externalOld193SourceConfig)
	validated, fingerprint, err := externalBootstrapSourceConfig(raw)
	if err != nil || validated.SchemaVersion != config.CurrentSchemaVersion || validated.Revision != 1 || !validated.SafeMode || !validated.ServiceControl.Stopped {
		t.Fatal("strict semantic source validation changed", err)
	}
	if fingerprint == "" || fingerprint == ConfigFingerprint(validated) {
		t.Fatal("source fingerprint describes future normalized config")
	}
	root := t.TempDir()
	path := filepath.Join(root, "config.json")
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	record := updateRecord{ConfigFingerprint: fingerprint, Job: Job{ConfigRevision: validated.Revision}, Deployment: Deployment{Paths: map[string]string{"config": path}}}
	wrong := record
	wrong.ConfigFingerprint = ConfigFingerprint(validated)
	if helperConfigMatches(wrong) || !helperConfigMatches(record) {
		t.Fatal("unchanged real legacy source cannot satisfy its original helper guard")
	}
	header, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	for _, changed := range []string{
		strings.Replace(externalOld193SourceConfig, `"revision":1`, `"revision":2`, 1),
		strings.Replace(externalOld193SourceConfig, `"safe_mode":true`, `"safe_mode":false`, 1),
		strings.Replace(externalOld193SourceConfig, `"stopped":true`, `"stopped":false`, 1),
		strings.Replace(externalOld193SourceConfig, `"schema_version":1`, `"schema_version":2`, 1),
	} {
		if err := os.WriteFile(path, []byte(changed), 0600); err != nil {
			t.Fatal(err)
		}
		if helperConfigMatches(record) {
			t.Fatal("source mutation adopted by original header")
		}
	}
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	staged := filepath.Join(root, "staged.json")
	if err := os.WriteFile(staged, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if report, err := config.Migrate(staged); err != nil || !report.Changed {
		t.Fatal("actual staged migration", report, err)
	}
	migrated, err := os.ReadFile(staged)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := inspectFileMigrationMode(raw, migrated, 1, true); err != nil {
		t.Fatal("staged intent/revision changed", err)
	}
	sourceAfter, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	afterHeader, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(sourceAfter, raw) || !bytes.Equal(header, afterHeader) || !helperConfigMatches(record) || bytes.Equal(raw, migrated) {
		t.Fatal("staged migration rewrote source/header or did not migrate")
	}
}

func TestExternalBootstrapSourceConfigCurrentAndRefusals(t *testing.T) {
	current := config.Default()
	current.Revision = 1
	raw, err := json.Marshal(current)
	if err != nil {
		t.Fatal(err)
	}
	validated, fingerprint, err := externalBootstrapSourceConfig(raw)
	if err != nil || fingerprint != ConfigFingerprint(current) || fingerprint != ConfigFingerprint(validated) {
		t.Fatal("already-current config fingerprint changed", err)
	}
	for _, invalid := range []string{
		strings.Replace(externalOld193SourceConfig, `"schema_version":1`, `"schema_version":999`, 1),
		strings.Replace(externalOld193SourceConfig, `"schema_version":1`, `"schema_version":-1`, 1),
		strings.Replace(externalOld193SourceConfig, `"revision":1`, `"revision":0`, 1),
		strings.Replace(externalOld193SourceConfig, `"revision":1`, `"revision":1,"unknown_new_field":true`, 1),
		externalOld193SourceConfig + " {}",
		"{",
	} {
		if _, fingerprint, err := externalBootstrapSourceConfig([]byte(invalid)); err == nil || fingerprint != "" {
			t.Fatal("invalid source acquired fingerprint", err)
		}
	}
}
