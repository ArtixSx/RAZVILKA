package app

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ArtixSx/razvilka/internal/auditlog"
	"github.com/ArtixSx/razvilka/internal/cloudflareprovider"
	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/security"
)

const cloudflareTestToken = "0123456789abcdefghijklmnopqrstuvwxyz-ADMIN"

func cloudflareTestApp(t *testing.T) (*App, string) {
	t.Helper()
	root := t.TempDir()
	privatePath := filepath.Join(root, "private")
	if err := os.Mkdir(privatePath, 0o700); err != nil {
		t.Fatal(err)
	}
	copies, err := cloudflareprovider.OpenStore(privatePath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = copies.Close() })
	gate, err := security.NewGate(cloudflareTestToken)
	if err != nil {
		t.Fatal(err)
	}
	store, err := config.Load(filepath.Join(root, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	return &App{Cloudflare: copies, Security: gate, Store: store, Audit: auditlog.New(filepath.Join(root, "audit.jsonl"))}, privatePath
}

func cloudflareTestRequest(a *App, method, path, body string, authenticate bool) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, "http://router.local"+path, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Origin", "http://router.local")
	if authenticate {
		r.Header.Set("Authorization", "Bearer "+cloudflareTestToken)
	}
	w := httptest.NewRecorder()
	a.Handler(http.NotFoundHandler()).ServeHTTP(w, r)
	return w
}

func cloudflareFixture() string {
	return "[Interface]\nPrivateKey = " + base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{17}, 32)) + "\nAddress = 172.16.0.2/32\n[Peer]\nPublicKey = " + base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{42}, 32)) + "\nAllowedIPs = 0.0.0.0/0\nEndpoint = 162.159.192.1:2408\n"
}

func cloudflareBody(content string, save bool) string {
	input := map[string]string{"source_kind": cloudflareprovider.SourceWireGuard, "content": content}
	if save {
		input["confirm"] = "SAVE_ACCOUNT_COPY"
	}
	body, _ := json.Marshal(input)
	return string(body)
}

func TestCloudflareAPIRequiresAuthEvenBeforeSetup(t *testing.T) {
	a, _ := cloudflareTestApp(t)
	for _, nilGate := range []bool{false, true} {
		if nilGate {
			a.Security = nil
		}
		for _, route := range []struct{ method, path string }{
			{http.MethodGet, "/api/v1/cloudflare/accounts"},
			{http.MethodPost, "/api/v1/cloudflare/import/preview"},
			{http.MethodPost, "/api/v1/cloudflare/import"},
		} {
			w := cloudflareTestRequest(a, route.method, route.path, cloudflareBody(cloudflareFixture(), true), false)
			if w.Code != http.StatusUnauthorized {
				t.Fatalf("nil=%v path=%s code=%d", nilGate, route.path, w.Code)
			}
			if w.Header().Get("Cache-Control") != "no-store" {
				t.Fatal("auth error may be cached")
			}
		}
	}
	accounts, err := a.Cloudflare.List(context.Background())
	if err != nil || len(accounts) != 0 {
		t.Fatal("unauthorized requests changed snapshots")
	}
}

func TestCloudflareCopyPreviewImportAndListNeverActivateOrLeak(t *testing.T) {
	a, privatePath := cloudflareTestApp(t)
	before, _ := json.Marshal(a.Store.Get())
	content := cloudflareFixture()
	for _, action := range []string{"/import/preview", "/import", "/import"} {
		w := cloudflareTestRequest(a, http.MethodPost, "/api/v1/cloudflare"+action, cloudflareBody(content, action == "/import"), true)
		if w.Code != http.StatusOK {
			t.Fatalf("%s: %d %s", action, w.Code, w.Body.String())
		}
		if w.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("missing private cache policy")
		}
		var result struct {
			Account  cloudflareprovider.Account `json:"account"`
			CopyOnly bool                       `json:"copy_only"`
			Saved    bool                       `json:"saved"`
		}
		if json.Unmarshal(w.Body.Bytes(), &result) != nil || !result.CopyOnly || result.Saved != (action == "/import") || result.Account.Verification != "imported-unverified" {
			t.Fatal("false readiness or invalid copy contract")
		}
		if action == "/import/preview" {
			entries, _ := os.ReadDir(privatePath)
			if len(entries) != 0 {
				t.Fatal("preview persisted private data")
			}
		}
		if strings.Contains(w.Body.String(), base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{17}, 32))) || strings.Contains(w.Body.String(), "162.159.192.1") {
			t.Fatal("secret/raw input leaked in API response")
		}
	}
	w := cloudflareTestRequest(a, http.MethodGet, "/api/v1/cloudflare/accounts", "", true)
	var result struct {
		Accounts []cloudflareprovider.Account `json:"accounts"`
	}
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &result) != nil || len(result.Accounts) != 1 {
		t.Fatal("identical input created duplicate or list failed")
	}
	after, _ := json.Marshal(a.Store.Get())
	if !bytes.Equal(before, after) {
		t.Fatal("copy import changed draft/live config")
	}
	journal, err := os.ReadFile(a.Audit.Path)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{17}, 32)), "162.159.192.1", "SAVE_ACCOUNT_COPY"} {
		if bytes.Contains(journal, []byte(secret)) {
			t.Fatal("audit leaked request content")
		}
	}
}

func TestCloudflareAPIRejectsMalformedRequestsWithoutWrites(t *testing.T) {
	a, privatePath := cloudflareTestApp(t)
	valid := cloudflareBody(cloudflareFixture(), true)
	for _, input := range []string{
		valid + `{}`, strings.Replace(valid, `"confirm":`, `"confirm":"SAVE_ACCOUNT_COPY","confirm":`, 1),
		strings.Replace(valid, `"content":`, `"Content":`, 1), strings.Replace(valid, `"confirm":"SAVE_ACCOUNT_COPY",`, "", 1),
		`{"source_kind":"usque-session","content":"private-secret","url":"https://example.com/private-secret"}`,
		`{"source_kind":"wireguard-profile","content":null,"confirm":"SAVE_ACCOUNT_COPY"}`,
		cloudflareBody(strings.Repeat("private-secret", 30000), true),
		strings.Repeat(" ", cloudflareprovider.MaxImportBytes*6+2048),
		"{\"content\":\"\xff\"}",
	} {
		w := cloudflareTestRequest(a, http.MethodPost, "/api/v1/cloudflare/import", input, true)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("malformed request accepted: status=%d", w.Code)
		}
		if strings.Contains(w.Body.String(), "private-secret") {
			t.Fatal("error leaked input")
		}
	}
	entries, _ := os.ReadDir(privatePath)
	if len(entries) != 0 {
		t.Fatal("invalid requests wrote private files")
	}
}

func TestCloudflareAPIOriginMediaBusyAndDisabled(t *testing.T) {
	a, _ := cloudflareTestApp(t)
	for _, mutation := range []struct {
		origin, media string
		want          int
	}{
		{"https://evil.example", "application/json", http.StatusForbidden},
		{"http://router.local", "text/plain", http.StatusUnsupportedMediaType},
	} {
		r := httptest.NewRequest(http.MethodPost, "http://router.local/api/v1/cloudflare/import", strings.NewReader(cloudflareBody(cloudflareFixture(), true)))
		r.Header.Set("Authorization", "Bearer "+cloudflareTestToken)
		r.Header.Set("Origin", mutation.origin)
		r.Header.Set("Content-Type", mutation.media)
		w := httptest.NewRecorder()
		a.Handler(http.NotFoundHandler()).ServeHTTP(w, r)
		if w.Code != mutation.want {
			t.Fatalf("unsafe request status=%d", w.Code)
		}
	}
	a.cloudflareBusy.Store(true)
	w := cloudflareTestRequest(a, http.MethodPost, "/api/v1/cloudflare/import", cloudflareBody(cloudflareFixture(), true), true)
	if w.Code != http.StatusTooManyRequests || w.Header().Get("Retry-After") == "" {
		t.Fatal("concurrent parser was not bounded")
	}
	a.cloudflareBusy.Store(false)
	a.Cloudflare = nil
	w = cloudflareTestRequest(a, http.MethodGet, "/api/v1/cloudflare/accounts", "", true)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatal("disabled store claimed availability")
	}
}
