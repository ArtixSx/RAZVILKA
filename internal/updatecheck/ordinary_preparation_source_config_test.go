package updatecheck

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/ArtixSx/razvilka/internal/config"
)

func TestOrdinaryPreparationInstalledSourceConfigMigration(t *testing.T) {
	// Use the actual installer input, not a separately reconstructed current
	// config. LoadExisting intentionally normalizes only the in-memory image.
	raw, err := os.ReadFile(filepath.Join("..", "..", "configs", "config.example.json"))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	store, err := config.LoadExisting(path)
	if err != nil {
		t.Fatal(err)
	}
	expected := store.Get()
	record := updateRecord{ConfigFingerprint: ConfigFingerprint(expected), Job: Job{ConfigRevision: expected.Revision}, Deployment: Deployment{Paths: map[string]string{"config": path}}}
	header, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	unmigrated, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(raw, unmigrated) || expected.SchemaVersion != config.CurrentSchemaVersion || helperConfigMatches(record) {
		t.Fatal("unmigrated example unexpectedly satisfied the original source guard", err)
	}
	// This is the operation performed by the public -migrate-config command
	// during installation, before any ordinary update obtains its owner.
	report, err := config.Migrate(path)
	if err != nil || !report.Changed || !helperConfigMatches(record) {
		t.Fatal("installed source did not satisfy the unchanged owner", report, err)
	}
	actual, _, err := config.Inspect(path)
	if err != nil || !reflect.DeepEqual(actual, expected) {
		t.Fatal("migration changed the intended source settings", err)
	}
	migrated, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	report, err = config.Migrate(path)
	if err != nil || report.Changed {
		t.Fatal("repeat migration was not a no-op", report, err)
	}
	repeated, readErr := os.ReadFile(path)
	afterHeader, marshalErr := json.Marshal(record)
	if readErr != nil || marshalErr != nil || !bytes.Equal(migrated, repeated) || !bytes.Equal(header, afterHeader) || !helperConfigMatches(record) {
		t.Fatal("repeat migration changed source or reviewed identity", readErr, marshalErr)
	}
	actual.Revision++
	changed, err := json.Marshal(actual)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, changed, 0600); err != nil {
		t.Fatal(err)
	}
	if helperConfigMatches(record) {
		t.Fatal("source revision change escaped the original owner guard")
	}
}
