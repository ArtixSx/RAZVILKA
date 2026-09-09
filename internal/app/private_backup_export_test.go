package app

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/ArtixSx/razvilka/internal/engineconfig"
	"github.com/ArtixSx/razvilka/internal/privatebackup"
)

// Stage every allowlisted slot so these tests never depend on host /opt files.
func stagePrivateBackupExportFixture(t *testing.T, a *App) int {
	t.Helper()
	count := 0
	for _, engine := range engineconfig.Specs() {
		for _, file := range engine.Files {
			content := map[string]string{"json": `{}`, "ini": "[Interface]\nPrivateKey = synthetic-private-marker\n", "shell": "#!/bin/sh\nexit 0\n", "list": "fixture.example\n", "cidr-list": "203.0.113.0/24\n"}[file.Syntax]
			if engine.ID == "amneziawg" {
				content = awgTestProfile()
			}
			if content == "" {
				t.Fatal("fixture has no known validator")
			}
			if _, err := a.EngineConfigs.Stage(engine.ID, file.ID, content); err != nil {
				t.Fatal(err)
			}
			count++
		}
	}
	return count
}

func requestPrivateBackupExport(a *App) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	a.Handler(http.NotFoundHandler()).ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/api/v1/private-backups/export", strings.NewReader(`{"password":"correct horse battery staple"}`)))
	return w
}

func TestPrivateBackupExportRejectsInvalidDraftWithoutChangingIt(t *testing.T) {
	for _, fixture := range []struct{ name, engine, file, content string }{
		{"unfinished-json", "sing-box", "main", "private-content-must-not-escape{"},
		{"empty-json", "sing-box", "main", ""},
		{"private-cidr-validation-error", "nfqws2", "ipset-list", "private-content-must-not-escape"},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			a, _ := privateRestoreTestApp(t)
			stagePrivateBackupExportFixture(t, a)
			if _, err := a.EngineConfigs.Stage(fixture.engine, fixture.file, fixture.content); err != nil {
				t.Fatal(err)
			}
			before := a.Store.Get()
			w := requestPrivateBackupExport(a)
			if w.Code != http.StatusUnprocessableEntity || w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("Content-Disposition") != "" {
				t.Fatalf("invalid source was advertised as a backup: HTTP %d", w.Code)
			}
			var result map[string]any
			if json.Unmarshal(w.Body.Bytes(), &result) != nil || result["code"] != "PRIVATE_BACKUP_ENGINE_INVALID" || result["engine_id"] != fixture.engine || result["file_id"] != fixture.file || result["source"] != "staged" {
				t.Fatal("missing bounded source identity")
			}
			if !strings.Contains(w.Body.String(), "незавершённый черновик") || strings.Contains(w.Body.String(), "private-content") || strings.Contains(w.Body.String(), "secret-path-marker") || strings.Contains(w.Body.String(), "ciphertext") {
				t.Fatal("export exposed private bytes or omitted repair context")
			}
			current, err := a.EngineConfigs.ReadExpert(fixture.engine, fixture.file)
			if err != nil || current.Content != fixture.content || !reflect.DeepEqual(before, a.Store.Get()) {
				t.Fatal("failed export changed the draft or services")
			}
		})
	}
}

func TestPrivateBackupExportRejectsUnreadableFileWithoutOmittingIt(t *testing.T) {
	a, _ := privateRestoreTestApp(t)
	stagePrivateBackupExportFixture(t, a)
	target := filepath.Join(a.EngineConfigs.StageRoot, "sing-box", "main.draft")
	if err := os.Remove(target); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(target, "private-marker")
	if err := os.WriteFile(marker, []byte("preserve private bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	before := a.Store.Get()
	w := requestPrivateBackupExport(a)
	var result map[string]any
	if w.Code != http.StatusServiceUnavailable || json.Unmarshal(w.Body.Bytes(), &result) != nil || result["code"] != "PRIVATE_BACKUP_ENGINE_UNREADABLE" || result["engine_id"] != "sing-box" {
		t.Fatalf("unreadable source was omitted: HTTP %d", w.Code)
	}
	if strings.Contains(w.Body.String(), "secret-path-marker") || strings.Contains(w.Body.String(), "private-marker") || strings.Contains(w.Body.String(), "ciphertext") {
		t.Fatal("unreadable export exposed private path/data")
	}
	got, err := os.ReadFile(marker)
	if err != nil || string(got) != "preserve private bytes" || !reflect.DeepEqual(before, a.Store.Get()) {
		t.Fatal("failed export modified the unreadable source")
	}
}

func TestPrivateBackupExportValidEngineFilesPassPreview(t *testing.T) {
	a, _ := privateRestoreTestApp(t)
	wantFiles := stagePrivateBackupExportFixture(t, a)
	w := requestPrivateBackupExport(a)
	if w.Code != http.StatusOK {
		t.Fatalf("valid source export failed: HTTP %d", w.Code)
	}
	var envelope privatebackup.Envelope
	if json.Unmarshal(w.Body.Bytes(), &envelope) != nil {
		t.Fatal("invalid encrypted envelope")
	}
	payload, err := privatebackup.Decrypt(envelope, "correct horse battery staple")
	if err != nil || len(payload.EngineFiles) != wantFiles {
		t.Fatal("successful export omitted an engine file")
	}
	body, _ := json.Marshal(map[string]any{"envelope": envelope, "password": "correct horse battery staple"})
	preview := httptest.NewRecorder()
	a.Handler(http.NotFoundHandler()).ServeHTTP(preview, httptest.NewRequest(http.MethodPost, "/api/v1/private-backups/preview", bytes.NewReader(body)))
	if preview.Code != http.StatusOK || !strings.Contains(preview.Body.String(), `"valid":true`) || strings.Contains(preview.Body.String(), "synthetic-private-marker") {
		t.Fatalf("generated backup is not safely previewable: HTTP %d", preview.Code)
	}
}
