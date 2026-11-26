package updatecheck

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/ownedfs"
)

func TestExternalBootstrapPreparationCapabilitiesKeepOrdinarySchemaFence(t *testing.T) {
	metadata := map[string]string{
		"-self-update-schema": "0\n", "-self-update-read-version": "4\n", "-component-update-schema": "3\n",
		"-node-history-read-version": "3\n", "-native-enrollment-schema": "1\n", "-subscription-schema": "1\n",
	}
	probe := func(_ context.Context, _ string, flag string) (string, error) { return metadata[flag], nil }
	if err := checkExternalBootstrapCapabilities(context.Background(), "verified-candidate", 3, 3, probe); err != nil {
		t.Fatal("truthful paired reader was rejected", err)
	}
	if err := checkFileCapabilitiesForHistories(context.Background(), "verified-candidate", 3, 3, probe); err == nil {
		t.Fatal("paired metadata granted ordinary schema2 admission")
	}
	for _, tc := range []struct{ flag, value string }{
		{"-self-update-schema", "2\n"}, {"-self-update-read-version", "3\n"},
		{"-component-update-schema", "2\n"}, {"-node-history-read-version", "2\n"},
		{"-native-enrollment-schema", "0\n"}, {"-subscription-schema", "0\n"},
	} {
		t.Run(tc.flag, func(t *testing.T) {
			previous := metadata[tc.flag]
			metadata[tc.flag] = tc.value
			defer func() { metadata[tc.flag] = previous }()
			if err := checkExternalBootstrapCapabilities(context.Background(), "verified-candidate", 3, 3, probe); err == nil {
				t.Fatal("incompatible candidate metadata was accepted")
			}
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	called := false
	err := checkExternalBootstrapCapabilities(ctx, "verified-candidate", 2, 2, func(context.Context, string, string) (string, error) {
		called = true
		return "", nil
	})
	if !errors.Is(err, context.Canceled) || called {
		t.Fatal("cancelled preparation executed a candidate", err)
	}
	cause := errors.New("private probe failure")
	err = checkExternalBootstrapCapabilities(context.Background(), "verified-candidate", 2, 2, func(context.Context, string, string) (string, error) { return "", cause })
	if !errors.Is(err, cause) {
		t.Fatal("original capability error was discarded", err)
	}
}

func TestExternalBootstrapPreparationCannotBeCopiedOrRenewed(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	called := false
	p := &externalBootstrapPreparation{
		adapter:  &SelfUpdateFileAdapter{installation: "/opt", directory: productionUpdateRoot, fileJournal: productionFileJournal},
		original: ctx, owner: func(context.Context, string) error { called = true; return nil },
	}
	p.self = p
	copied := *p
	renewed, stop := context.WithTimeout(context.Background(), time.Minute)
	defer stop()
	for _, tc := range []struct {
		name string
		cap  *externalBootstrapPreparation
		ctx  context.Context
	}{{"nil", nil, ctx}, {"copy", &copied, ctx}, {"fresh-context", p, renewed}} {
		t.Run(tc.name, func(t *testing.T) {
			if !errors.Is(tc.cap.current(tc.ctx), ErrExternalBootstrap) || called {
				t.Fatal("unbound capability reached ownership/effects")
			}
		})
	}
	if _, err := newExternalBootstrapPreparation(p.adapter, context.Background(), updateRecord{}, nil, fileProcess{}, fileProcess{}, "", "", "", p.owner); !errors.Is(err, ErrExternalBootstrap) || called {
		t.Fatal("nonfinite context could construct preparation", err)
	}
}

func TestExternalBootstrapPublicationRetainsExactOwnerHeader(t *testing.T) {
	root, err := ownedfs.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	record := updateRecord{Owner: updaterOwner, CurrentVersion: "0.19.3", ParentPID: 123,
		Job: Job{ID: strings.Repeat("a", 32), State: "preparing", Stage: "metadata", CanCancel: true, UpdatedAt: time.Unix(1, 0)}}
	if err := writeInitialExternalBootstrap(root, record); err != nil {
		t.Fatal(err)
	}
	record.Job.Stage = "preflight"
	if err := publishExternalBootstrapHeader(context.Background(), root, &record, "preparing"); err != nil {
		t.Fatal(err)
	}
	expected, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	published, err := root.ReadLimited("current.json", 64<<10)
	if err != nil || !bytes.Equal(published, expected) || record.Job.UpdatedAt.Equal(time.Unix(1, 0)) {
		t.Fatal("original owner retained a different header from its publication", err)
	}
}

func TestExternalBootstrapPreparationUsesActualCatalogAndMigrationParsers(t *testing.T) {
	bundle := t.TempDir()
	if err := os.Mkdir(filepath.Join(bundle, "configs"), 0700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"service-catalog.json", "sources.json", "community-catalog.json"} {
		data, err := os.ReadFile(filepath.Join("../../configs", name))
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(bundle, "configs", name)
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := inspectExternalBootstrapCatalogs(bundle); err != nil {
		t.Fatal("actual release catalogs rejected", err)
	}
	for _, name := range []string{"service-catalog.json", "sources.json", "community-catalog.json"} {
		path := filepath.Join(bundle, "configs", name)
		original, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		invalid := []byte(`{"schema":999}`)
		if name == "service-catalog.json" {
			invalid = []byte(`{"services":[{}]}`)
		}
		if err := os.WriteFile(path, invalid, 0600); err != nil {
			t.Fatal(err)
		}
		if err := inspectExternalBootstrapCatalogs(bundle); err == nil {
			t.Fatal("catalog validation was waived", name)
		}
		if err := os.WriteFile(path, original, 0600); err != nil {
			t.Fatal(err)
		}
	}
	// This only tests the genuine parser and migration contract. It cannot mint
	// original producer authority or stand in for the public native gate.
	old := []byte(`{"schema_version":1,"revision":1,"listen":":8787","services":{},"applied_services":{},"engine_order":["nfqws2"],"safe_mode":true,"service_control":{"mode":"manual","stopped":false}}`)
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, old, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := config.Migrate(path); err != nil {
		t.Fatal("genuine staged migration refused", err)
	}
	migrated, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := inspectFileMigrationMode(old, migrated, 1, true); err != nil {
		t.Fatal("migration changed reviewed intent/revision", err)
	}
	cfg, _, err := config.InspectBytes(migrated)
	if err != nil || cfg.Revision != 1 || !cfg.SafeMode || cfg.ServiceControl.Stopped || cfg.ServiceControl.Mode != "manual" {
		t.Fatal("staged migration forged Stop or erased manual intent", err)
	}
}

func TestExternalBootstrapFailurePreservesCauseAndClosesDiagnosticVocabulary(t *testing.T) {
	cause := errors.New("private package path and command output")
	err := externalBootstrapFailure("file-review", externalBootstrapFailure("staged-migration", cause))
	if !errors.Is(err, cause) || !errors.Is(err, ErrExternalBootstrap) || ExternalBootstrapFailureCategory(err) != "staged-migration" {
		t.Fatal("staging cause/category lost")
	}
	err = externalBootstrapFailure("unknown "+cause.Error(), cause)
	if !errors.Is(err, cause) || err.Error() != "external-bootstrap-refused" {
		t.Fatal("private error escaped the diagnostic vocabulary")
	}
}
