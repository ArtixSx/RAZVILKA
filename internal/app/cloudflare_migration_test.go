package app

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ArtixSx/razvilka/internal/cloudflareprovider"
)

func migrationTestApp(t *testing.T) (*App, string, string) {
	t.Helper()
	a, destination := cloudflareTestApp(t)
	path := filepath.Join(t.TempDir(), "source.conf")
	if err := os.WriteFile(path, []byte(cloudflareFixture()), 0o600); err != nil {
		t.Fatal(err)
	}
	var err error
	a.CloudflareLegacy, err = cloudflareprovider.NewLegacySources([]cloudflareprovider.LegacySpec{{ID: "fixture", Label: "Synthetic local profile", Kind: cloudflareprovider.SourceWireGuard, Path: path}})
	if err != nil {
		t.Fatal(err)
	}
	return a, path, destination
}

func TestLegacyAPICopiesWithoutRouteOrSourceMutation(t *testing.T) {
	a, path, destination := migrationTestApp(t)
	before := cfArchiveJSON(a.Store.Get())
	w := cloudflareTestRequest(a, "GET", "/api/v1/cloudflare/legacy/sources", "", true)
	if w.Code != 200 || strings.Contains(w.Body.String(), path) || strings.Contains(w.Body.String(), "PrivateKey") {
		t.Fatal("unsafe source inventory")
	}
	w = cloudflareTestRequest(a, "POST", "/api/v1/cloudflare/legacy/preview", `{"source_id":"fixture"}`, true)
	if w.Code != 200 {
		t.Fatalf("preview: %d %s", w.Code, w.Body.String())
	}
	var result struct {
		Review cloudflareprovider.LegacyReview `json:"review"`
	}
	if json.Unmarshal(w.Body.Bytes(), &result) != nil || result.Review.Account.ID != "" {
		t.Fatal("preview persisted account")
	}
	files, _ := os.ReadDir(destination)
	if len(files) != 0 {
		t.Fatal("preview wrote files")
	}
	input := map[string]string{"source_id": "fixture", "review_digest": result.Review.Digest, "confirm": "COPY_LEGACY_ACCOUNT"}
	for n := 0; n < 2; n++ {
		w = cloudflareTestRequest(a, "POST", "/api/v1/cloudflare/legacy/copy", cfArchiveJSON(input), true)
		if w.Code != 200 || w.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("copy: %d", w.Code)
		}
	}
	accounts, err := a.Cloudflare.List(context.Background())
	if err != nil || len(accounts) != 1 {
		t.Fatal("copy not idempotent")
	}
	if cfArchiveJSON(a.Store.Get()) != before {
		t.Fatal("migration changed routing")
	}
	raw, _ := os.ReadFile(path)
	if string(raw) != cloudflareFixture() {
		t.Fatal("migration changed source")
	}
	journal, _ := os.ReadFile(a.Audit.Path)
	for _, secret := range []string{path, "COPY_LEGACY_ACCOUNT", "PrivateKey", result.Review.Digest} {
		if strings.Contains(string(journal), secret) {
			t.Fatal("audit leaked private request")
		}
	}
	if err := os.WriteFile(path, append(raw, []byte("\n# replaced")...), 0o600); err != nil {
		t.Fatal(err)
	}
	w = cloudflareTestRequest(a, "POST", "/api/v1/cloudflare/legacy/copy", cfArchiveJSON(input), true)
	if w.Code != 409 {
		t.Fatal("changed source accepted")
	}
}

func TestLegacyAPIAccessAndInputBoundaries(t *testing.T) {
	a, _, destination := migrationTestApp(t)
	for _, action := range []string{"sources", "preview", "copy"} {
		method := "POST"
		if action == "sources" {
			method = "GET"
		}
		path := "/api/v1/cloudflare/legacy/" + action
		w := cloudflareTestRequest(a, method, path, `{}`, false)
		if w.Code != 401 || w.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("auth %s: %d", action, w.Code)
		}
		if method == "POST" {
			for _, boundary := range []struct {
				origin, media string
				status        int
			}{{"https://foreign.example", "application/json", 403}, {"http://router.local", "text/plain", 415}} {
				r := httptest.NewRequest(method, "http://router.local"+path, strings.NewReader(`{}`))
				r.Header.Set("Authorization", "Bearer "+cloudflareTestToken)
				r.Header.Set("Origin", boundary.origin)
				r.Header.Set("Content-Type", boundary.media)
				w := httptest.NewRecorder()
				a.Handler(http.NotFoundHandler()).ServeHTTP(w, r)
				if w.Code != boundary.status {
					t.Fatal("request boundary failed")
				}
			}
		}
	}
	for _, body := range []string{`{"source_id":"../source.conf"}`, `{"source_id":"fixture","path":"/etc/passwd"}`, `{"source_id":"fixture","source_id":"fixture"}`, `{"Source_ID":"fixture"}`, `{"source_id":null}`, `{"source_id":"fixture"} {}`, strings.Repeat(" ", 2049)} {
		w := cloudflareTestRequest(a, "POST", "/api/v1/cloudflare/legacy/preview", body, true)
		if w.Code != 400 {
			t.Fatalf("invalid input accepted: %d", w.Code)
		}
	}
	w := cloudflareTestRequest(a, "POST", "/api/v1/cloudflare/legacy/copy", `{"source_id":"fixture"}`, true)
	if w.Code != 400 {
		t.Fatal("unreviewed copy accepted")
	}
	a.cloudflareBusy.Store(true)
	w = cloudflareTestRequest(a, "POST", "/api/v1/cloudflare/legacy/preview", `{"source_id":"fixture"}`, true)
	if w.Code != 429 {
		t.Fatal("unbounded legacy read")
	}
	a.cloudflareBusy.Store(false)
	a.Security = nil
	w = cloudflareTestRequest(a, "GET", "/api/v1/cloudflare/legacy/sources", "", false)
	if w.Code != 401 {
		t.Fatal("nil auth accepted")
	}
	files, _ := os.ReadDir(destination)
	if len(files) != 0 {
		t.Fatal("invalid request wrote copies")
	}
}
