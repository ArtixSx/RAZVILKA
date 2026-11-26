package app

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/ArtixSx/razvilka/internal/cloudflareprovider"
	"github.com/ArtixSx/razvilka/internal/privatebackup"
)

const cfArchivePassword = "synthetic archive test password"

func cfArchiveJSON(value any) string { data, _ := json.Marshal(value); return string(data) }

func TestCloudflareBackupAPIRoundtripWithoutRouterChanges(t *testing.T) {
	a, _ := cloudflareTestApp(t)
	parsed, _ := cloudflareprovider.ParseImport(cloudflareprovider.SourceWireGuard, []byte(cloudflareFixture()))
	if _, err := a.Cloudflare.ImportSnapshot(context.Background(), parsed); err != nil {
		t.Fatal(err)
	}
	w := cloudflareTestRequest(a, "POST", "/api/v1/cloudflare/backups/export", cfArchiveJSON(map[string]string{"password": cfArchivePassword}), true)
	if w.Code != 200 || w.Header().Get("Content-Disposition") == "" || strings.Contains(w.Body.String(), "PrivateKey") {
		t.Fatalf("export: %d", w.Code)
	}
	var envelope privatebackup.Envelope
	if err := json.Unmarshal(w.Body.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	b, path := cloudflareTestApp(t)
	before := cfArchiveJSON(b.Store.Get())
	input := map[string]any{"password": cfArchivePassword, "envelope": envelope}
	w = cloudflareTestRequest(b, "POST", "/api/v1/cloudflare/backups/preview", cfArchiveJSON(input), true)
	if w.Code != 200 {
		t.Fatalf("preview: %d %s", w.Code, w.Body.String())
	}
	var result struct {
		Review cloudflareprovider.BackupReview `json:"review"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.Review.Added != 1 || result.Review.Existing != 0 {
		t.Fatalf("preview: %+v", result)
	}
	files, _ := os.ReadDir(path)
	if len(files) != 0 {
		t.Fatal("preview persisted data")
	}
	input["confirm"] = "RESTORE_ACCOUNT_COPIES"
	input["preview_digest"] = strings.Repeat("0", 64)
	w = cloudflareTestRequest(b, "POST", "/api/v1/cloudflare/backups/restore", cfArchiveJSON(input), true)
	if w.Code != http.StatusConflict {
		t.Fatalf("digest mismatch: %d", w.Code)
	}
	input["preview_digest"] = result.Review.Digest
	for n := 0; n < 2; n++ {
		w = cloudflareTestRequest(b, "POST", "/api/v1/cloudflare/backups/restore", cfArchiveJSON(input), true)
		if w.Code != 200 || w.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("restore: %d", w.Code)
		}
		if strings.Contains(w.Body.String(), "PrivateKey") || strings.Contains(w.Body.String(), cfArchivePassword) {
			t.Fatal("secret in restore response")
		}
	}
	accounts, err := b.Cloudflare.List(context.Background())
	if err != nil || len(accounts) != 1 {
		t.Fatalf("copies: %d %v", len(accounts), err)
	}
	if before != cfArchiveJSON(b.Store.Get()) {
		t.Fatal("copy restore changed router configuration")
	}
	journal, err := os.ReadFile(b.Audit.Path)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{cfArchivePassword, envelope.Ciphertext, "RESTORE_ACCOUNT_COPIES", "PrivateKey", "162.159.192.1"} {
		if strings.Contains(string(journal), secret) {
			t.Fatal("backup audit contains private request data")
		}
	}
	payload, err := privatebackup.Decrypt(envelope, cfArchivePassword)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.previewPrivateBackup(payload); err == nil {
		t.Fatal("general router restore accepted provider-only archive")
	}
	input["password"] = "incorrect archive password"
	delete(input, "confirm")
	delete(input, "preview_digest")
	w = cloudflareTestRequest(b, "POST", "/api/v1/cloudflare/backups/preview", cfArchiveJSON(input), true)
	if w.Code != 400 || strings.Contains(w.Body.String(), "incorrect archive password") {
		t.Fatalf("wrong password: %d", w.Code)
	}
}

func TestAllBackupAPIsShareNonQueuedCryptoGate(t *testing.T) {
	a, _ := cloudflareTestApp(t)
	release, ok := a.backupOperation(httptest.NewRecorder())
	if !ok {
		t.Fatal("gate unavailable")
	}
	for _, path := range []string{
		"/api/v1/private-backups/export", "/api/v1/private-backups/preview", "/api/v1/private-backups/import",
		"/api/v1/cloudflare/backups/export", "/api/v1/cloudflare/backups/preview", "/api/v1/cloudflare/backups/restore",
	} {
		w := cloudflareTestRequest(a, "POST", path, "invalid input must not be read", true)
		if w.Code != 429 || w.Header().Get("Retry-After") == "" || w.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("gate %s: %d", path, w.Code)
		}
		if a.cloudflareBusy.Load() {
			t.Fatal("rejected crypto request retained copy gate")
		}
	}
	release()
	w := cloudflareTestRequest(a, "POST", "/api/v1/cloudflare/backups/export", `{}`, true)
	if w.Code != 400 || a.privateBackupBusy.Load() || a.cloudflareBusy.Load() {
		t.Fatal("gate not released after failure")
	}
}

func TestCloudflareBackupRequestBoundaries(t *testing.T) {
	a, _ := cloudflareTestApp(t)
	for _, action := range []string{"export", "preview", "restore"} {
		path := "/api/v1/cloudflare/backups/" + action
		w := cloudflareTestRequest(a, "POST", path, `{}`, false)
		if w.Code != 401 || w.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("auth %s: %d", action, w.Code)
		}
		w = cloudflareTestRequest(a, "GET", path, `{}`, true)
		if w.Code != 405 {
			t.Fatalf("method %s: %d", action, w.Code)
		}
		for _, boundary := range []struct {
			origin, media string
			status        int
		}{
			{"https://foreign.example", "application/json", 403}, {"http://router.local", "text/plain", 415},
		} {
			r := httptest.NewRequest("POST", "http://router.local"+path, strings.NewReader(`{}`))
			r.Header.Set("Authorization", "Bearer "+cloudflareTestToken)
			r.Header.Set("Origin", boundary.origin)
			r.Header.Set("Content-Type", boundary.media)
			w := httptest.NewRecorder()
			a.Handler(http.NotFoundHandler()).ServeHTTP(w, r)
			if w.Code != boundary.status || w.Header().Get("Cache-Control") != "no-store" {
				t.Fatalf("request boundary %s: %d", action, w.Code)
			}
		}
	}
	for _, input := range []string{
		`{"password":"synthetic long password","Password":"alias"}`,
		`{"password":"synthetic long password","password":"duplicate"}`,
		`{"password":"synthetic long password"} {}`,
		`{"password":null}`, `{"password":"short"}`,
		`{"password":"` + strings.Repeat("x", 4096) + `"}`,
	} {
		w := cloudflareTestRequest(a, "POST", "/api/v1/cloudflare/backups/export", input, true)
		if w.Code != 400 {
			t.Fatalf("malformed request accepted: %d", w.Code)
		}
	}
	for _, nested := range []string{`null`, `[]`, `{"Kind":"alias"}`, `{"kind":"a","kind":"b"}`, `{"path":"/etc/passwd"}`} {
		w := cloudflareTestRequest(a, "POST", "/api/v1/cloudflare/backups/preview", `{"password":"synthetic long password","envelope":`+nested+`}`, true)
		if w.Code != 400 {
			t.Fatalf("nested request accepted: %d", w.Code)
		}
	}
	a.Security = nil
	w := cloudflareTestRequest(a, "POST", "/api/v1/cloudflare/backups/preview", `{}`, false)
	if w.Code != 401 {
		t.Fatal("nil authentication gate allowed archive request")
	}
}
