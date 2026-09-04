package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/customservices"
	"github.com/ArtixSx/razvilka/internal/devices"
	"github.com/ArtixSx/razvilka/internal/engineconfig"
	"github.com/ArtixSx/razvilka/internal/nodestore"
	"github.com/ArtixSx/razvilka/internal/privatebackup"
	"github.com/ArtixSx/razvilka/internal/privaterestore"
	"github.com/ArtixSx/razvilka/internal/restorejournal"
)

func TestPrivateRestoreStepFailureMatrix(t *testing.T) {
	for failAt := 0; failAt < 4; failAt++ {
		t.Run(fmt.Sprint(failAt), func(t *testing.T) {
			var calls []string
			var steps []privateRestoreStep
			for n := 0; n < 4; n++ {
				steps = append(steps, privateRestoreStep{phase: fmt.Sprint(n), apply: func() (func() error, error) {
					calls = append(calls, fmt.Sprintf("apply-%d", n))
					if n == failAt {
						return nil, errors.New("private-key-must-not-escape")
					}
					return func() error { calls = append(calls, fmt.Sprintf("undo-%d", n)); return nil }, nil
				}})
			}
			err := runPrivateRestore(context.Background(), steps)
			var failure *privateRestoreFailure
			if !errors.As(err, &failure) || failure.recoveryRequired {
				t.Fatalf("wrong result: %v", err)
			}
			var want []string
			for n := 0; n <= failAt; n++ {
				want = append(want, fmt.Sprintf("apply-%d", n))
			}
			for n := failAt - 1; n >= 0; n-- {
				want = append(want, fmt.Sprintf("undo-%d", n))
			}
			if !reflect.DeepEqual(calls, want) {
				t.Fatalf("order: %v expected %v", calls, want)
			}
			w := httptest.NewRecorder()
			writePrivateRestoreFailure(w, err)
			if strings.Contains(w.Body.String(), "private-key") || strings.Contains(fmt.Sprintf("%+v", err), "private-key") {
				t.Fatal("private cause escaped")
			}
		})
	}
}

func TestPrivateRestoreCanUndoCompletedEngineStep(t *testing.T) {
	for _, external := range []bool{false, true} {
		root := t.TempDir()
		manager := engineconfig.New(filepath.Join(root, "stage"), filepath.Join(root, "backup"))
		if _, err := manager.Stage("sing-box", "main", "{unfinished"); err != nil {
			t.Fatal(err)
		}
		err := runPrivateRestore(context.Background(), []privateRestoreStep{
			{"engine_files", func() (func() error, error) {
				_, undo, err := manager.StagePrivateWithRollback([]engineconfig.StageItem{{EngineID: "sing-box", FileID: "main", Content: `{"synthetic_secret":"imported"}`}})
				return undo, err
			}},
			{"later_phase", func() (func() error, error) {
				if external {
					other := engineconfig.New(manager.StageRoot, manager.BackupRoot)
					if _, err := other.Stage("sing-box", "main", `{"outside":true}`); err != nil {
						t.Fatal(err)
					}
				}
				return nil, errors.New("synthetic private failure")
			}},
		})
		var failure *privateRestoreFailure
		if !errors.As(err, &failure) || failure.recoveryRequired != external {
			t.Fatal("incorrect completed-stage undo result")
		}
		content, readErr := manager.ReadExpert("sing-box", "main")
		if readErr != nil {
			t.Fatal(readErr)
		}
		expected := "{unfinished"
		if external {
			expected = `{"outside":true}`
		}
		if content.Content != expected {
			t.Fatal("undo lost an old or later draft")
		}
		rec := httptest.NewRecorder()
		writePrivateRestoreFailure(rec, err)
		if strings.Contains(rec.Body.String(), "synthetic") || strings.Contains(rec.Body.String(), root) {
			t.Fatal("private cause leaked")
		}
	}
}

func TestPrivateRestoreIncompleteUndoAndCancellation(t *testing.T) {
	for _, mode := range []string{"undo-error", "engine-undo-error", "config-uncertain", "cancel-between", "cancel-after-commit"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			undone := 0
			err := runPrivateRestore(ctx, []privateRestoreStep{
				{"custom_services", func() (func() error, error) { return func() error { undone++; return nil }, nil }},
				{"services", func() (func() error, error) {
					if mode == "cancel-between" {
						cancel()
					}
					return func() error {
						undone++
						if mode == "undo-error" {
							return errors.New("newer state")
						}
						return nil
					}, nil
				}},
				{"engine_files", func() (func() error, error) {
					if mode == "cancel-after-commit" {
						cancel()
						return nil, nil
					}
					if mode == "engine-undo-error" {
						return nil, engineconfig.ErrStageRollback
					}
					if mode == "config-uncertain" {
						return nil, restorejournal.ErrRecovery
					}
					return nil, errors.New("write failed")
				}},
			})
			if mode == "cancel-after-commit" {
				if err != nil || undone != 0 {
					t.Fatal("committed final step was undone after disconnect")
				}
				return
			}
			var failure *privateRestoreFailure
			if !errors.As(err, &failure) || undone != 2 {
				t.Fatal("not all completed steps received undo")
			}
			if failure.recoveryRequired != (mode == "undo-error" || mode == "engine-undo-error" || mode == "config-uncertain") {
				t.Fatal("rollback result is not truthful")
			}
			w := httptest.NewRecorder()
			writePrivateRestoreFailure(w, err)
			var body map[string]any
			if json.Unmarshal(w.Body.Bytes(), &body) != nil || body["recovery_required"] != failure.recoveryRequired || body["rolled_back"] == failure.recoveryRequired {
				t.Fatal("incorrect public rollback result")
			}
		})
	}
}

func privateRestoreTestApp(t *testing.T) (*App, string) {
	t.Helper()
	root := t.TempDir()
	store, err := config.Load(filepath.Join(root, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	custom, err := customservices.Load(filepath.Join(root, "custom.json"))
	if err != nil {
		t.Fatal(err)
	}
	registry, err := devices.Load(filepath.Join(root, "devices.json"))
	if err != nil {
		t.Fatal(err)
	}
	a := &App{Store: store, CustomServices: custom, Devices: registry, Catalog: catalog.Catalog{Services: []catalog.Service{{ID: "youtube", Name: "YouTube"}}}, EngineConfigs: engineconfig.New(filepath.Join(root, "secret-path-marker"), filepath.Join(root, "backups"))}
	if err := store.UpdateService("youtube", config.ServiceState{Enabled: true, Route: "nfqws2"}); err != nil {
		t.Fatal(err)
	}
	if err := registry.MergeMetadata([]devices.Device{{ID: "test-device", Name: "Original"}}); err != nil {
		t.Fatal(err)
	}
	attachTestRestore(t, a, root)
	return a, root
}

func attachTestRestore(t *testing.T, a *App, root string) {
	t.Helper()
	nodeRoot := ""
	if a.Nodes != nil {
		nodeRoot = filepath.Join(root, "nodes")
	}
	c, _, err := privaterestore.Open(context.Background(), privaterestore.Layout{
		Config: filepath.Join(root, "config.json"), CustomServices: filepath.Join(root, "custom.json"), Devices: filepath.Join(root, "devices.json"),
		StageRoot: a.EngineConfigs.StageRoot, ProviderRoot: filepath.Join(root, "provider"), NodeRoot: nodeRoot, JournalRoot: filepath.Join(root, "journal"),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	if err := c.StartRuntime(); err != nil {
		t.Fatal(err)
	}
	a.PrivateRestore = c
}

func privateRestoreNodeApp(t *testing.T, root string) *App {
	t.Helper()
	store, err := config.Load(filepath.Join(root, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	custom, err := customservices.Load(filepath.Join(root, "custom.json"))
	if err != nil {
		t.Fatal(err)
	}
	registry, err := devices.Load(filepath.Join(root, "devices.json"))
	if err != nil {
		t.Fatal(err)
	}
	nodeRoot := filepath.Join(root, "nodes")
	if err := os.Mkdir(nodeRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	nodes, err := nodestore.Open(nodeRoot)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { nodes.Close() })
	a := &App{Store: store, CustomServices: custom, Devices: registry, Nodes: nodes, Catalog: catalog.Catalog{Services: []catalog.Service{{ID: "youtube", Name: "YouTube"}}}, EngineConfigs: engineconfig.New(filepath.Join(root, "stage"), filepath.Join(root, "backups"))}
	attachTestRestore(t, a, root)
	return a
}

func TestEncryptedPrivateBackupRoundTripsNodeStore(t *testing.T) {
	ctx := context.Background()
	source := privateRestoreNodeApp(t, filepath.Join(t.TempDir(), "source"))
	const privateURI = "vless://123e4567-e89b-12d3-a456-426614174000@node.example:443?security=tls&type=ws&path=%2Fprivate"
	if _, err := source.Nodes.Import(ctx, nodestore.Source{ID: "manual", Kind: "manual"}, privateURI, time.Date(2026, 9, 4, 0, 0, 0, 0, time.UTC), time.Hour, false); err != nil {
		t.Fatal(err)
	}
	exportBody, _ := json.Marshal(map[string]string{"password": "correct horse battery staple"})
	export := httptest.NewRecorder()
	source.Handler(http.NotFoundHandler()).ServeHTTP(export, httptest.NewRequest(http.MethodPost, "/api/v1/private-backups/export", bytes.NewReader(exportBody)))
	if export.Code != http.StatusOK || strings.Contains(export.Body.String(), "node.example") || strings.Contains(export.Body.String(), "123e4567") {
		t.Fatalf("unsafe node backup response: %d", export.Code)
	}
	var envelope privatebackup.Envelope
	if err := json.Unmarshal(export.Body.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	payload, err := privatebackup.Decrypt(envelope, "correct horse battery staple")
	if err != nil || payload.NodeSnapshot == nil {
		t.Fatal("encrypted backup omitted nodes", err)
	}
	target := privateRestoreNodeApp(t, filepath.Join(t.TempDir(), "target"))
	previewBody, _ := json.Marshal(map[string]any{"envelope": envelope, "password": "correct horse battery staple"})
	preview := httptest.NewRecorder()
	target.Handler(http.NotFoundHandler()).ServeHTTP(preview, httptest.NewRequest(http.MethodPost, "/api/v1/private-backups/preview", bytes.NewReader(previewBody)))
	if preview.Code != http.StatusOK || !strings.Contains(preview.Body.String(), `"nodes":1`) || strings.Contains(preview.Body.String(), "node.example") {
		t.Fatalf("node preview: %d %s", preview.Code, preview.Body.String())
	}
	importBody, _ := json.Marshal(map[string]any{"envelope": envelope, "password": "correct horse battery staple", "confirm": "IMPORT_PRIVATE_BACKUP"})
	imported := httptest.NewRecorder()
	target.Handler(http.NotFoundHandler()).ServeHTTP(imported, httptest.NewRequest(http.MethodPost, "/api/v1/private-backups/import", bytes.NewReader(importBody)))
	if imported.Code != http.StatusOK || !strings.Contains(imported.Body.String(), `"nodes_merged":1`) || strings.Contains(imported.Body.String(), "node.example") {
		t.Fatalf("node import: %d %s", imported.Code, imported.Body.String())
	}
	snapshot, err := target.Nodes.Snapshot(ctx, time.Date(2026, 9, 5, 0, 0, 0, 0, time.UTC))
	if err != nil || len(snapshot.Nodes) != 1 || snapshot.Nodes[0].State != "expired" || snapshot.Nodes[0].Health.State != "not_checked" {
		t.Fatal("restored nodes were lost or promoted")
	}
}

func privateRestoreFixture(t *testing.T) privatebackup.Payload {
	t.Helper()
	payload := privatebackup.NewPayload("0.18.1-dev")
	payload.Services = map[string]config.ServiceState{"youtube": {Enabled: true, Route: "usque"}}
	payload.CustomServices = []catalog.Service{{ID: "custom-test", Name: "Imported", Category: "Custom", Domains: []string{"import.example"}, Strategy: []string{"direct"}}}
	payload.Devices = []devices.Device{{ID: "test-device", Name: "Imported"}}
	payload.EngineFiles = []privatebackup.EngineFile{{EngineID: "nfqws2", FileID: "user-list", Content: "youtube.com\n", SHA256: privatebackup.Sum([]byte("youtube.com\n"))}}
	if err := privatebackup.Seal(&payload); err != nil {
		t.Fatal(err)
	}
	return payload
}

func TestPrivateRestoreHTTPFailedStagingUndoesOnlyItsWrites(t *testing.T) {
	a, root := privateRestoreTestApp(t)
	before := a.Store.Get()
	beforeDevices := a.Devices.Known()
	beforeCustom := a.CustomServices.List()
	// A regular file blocks the stage directory without needing administrator
	// privileges or permissions that root could ignore on Linux.
	if err := os.WriteFile(a.EngineConfigs.StageRoot, []byte("do-not-change"), 0o600); err != nil {
		t.Fatal(err)
	}
	payload := privateRestoreFixture(t)
	envelope, err := privatebackup.Encrypt(payload, "synthetic backup password")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(map[string]any{"envelope": envelope, "password": "synthetic backup password", "confirm": "IMPORT_PRIVATE_BACKUP"})
	r := httptest.NewRequest(http.MethodPost, "/api/v1/private-backups/import", bytes.NewReader(body))
	w := httptest.NewRecorder()
	a.privateBackupImport(w, r)
	if w.Code != 409 || !strings.Contains(w.Body.String(), "PRIVATE_BACKUP_IMPORT_NOT_STARTED") || strings.Contains(w.Body.String(), `"rolled_back":true`) {
		t.Fatalf("unexpected failure: %s", w.Body.String())
	}
	if w.Header().Get("Cache-Control") != "no-store" || strings.Contains(w.Body.String(), "secret-path-marker") || strings.Contains(w.Body.String(), root) {
		t.Fatal("private failure leaked path or can be cached")
	}
	if !reflect.DeepEqual(before, a.Store.Get()) || !reflect.DeepEqual(beforeDevices, a.Devices.Known()) || !reflect.DeepEqual(beforeCustom, a.CustomServices.List()) {
		t.Fatal("a completed step did not roll back")
	}
	content, _ := os.ReadFile(a.EngineConfigs.StageRoot)
	if string(content) != "do-not-change" {
		t.Fatal("obstruction changed")
	}
	reloaded, err := config.Load(filepath.Join(root, "config.json"))
	if err != nil || !reflect.DeepEqual(before, reloaded.Get()) {
		t.Fatal("rollback not persisted")
	}
}

func TestPrivateRestoreDoesNotClobberConcurrentServiceEdit(t *testing.T) {
	a, _ := privateRestoreTestApp(t)
	incoming := privateRestoreFixture(t)
	err := runPrivateRestore(context.Background(), []privateRestoreStep{
		{"services", func() (func() error, error) { return a.Store.ReplaceDraftWithRollback(incoming.Services) }},
		{"engine_files", func() (func() error, error) {
			if err := a.Store.UpdateService("youtube", config.ServiceState{Route: "direct"}); err != nil {
				t.Fatal(err)
			}
			return nil, errors.New("stage failure")
		}},
	})
	var failure *privateRestoreFailure
	if !errors.As(err, &failure) || !failure.recoveryRequired || a.Store.Get().Services["youtube"].Route != "direct" {
		t.Fatal("later service edit not preserved")
	}
}

func TestPrivateRestoreRejectsUnavailableDevicesAndProviderBeforeWrite(t *testing.T) {
	for _, kind := range []string{"devices", "provider"} {
		t.Run(kind, func(t *testing.T) {
			a, _ := privateRestoreTestApp(t)
			payload := privateRestoreFixture(t)
			if kind == "devices" {
				a.Devices = nil
			} else {
				payload.ProviderSnapshots = []privatebackup.ProviderSnapshot{{Provider: "cloudflare"}}
			}
			before := a.Store.Get()
			if _, err := a.previewPrivateBackup(payload); err == nil {
				t.Fatal("unsupported payload accepted by preview")
			}
			if err := a.restorePrivateDraft(context.Background(), payload); err == nil {
				t.Fatal("unsupported payload applied")
			}
			if !reflect.DeepEqual(before, a.Store.Get()) || len(a.CustomServices.List()) != 0 {
				t.Fatal("preflight mutated state")
			}
		})
	}
}
