package app

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/security"
	"github.com/ArtixSx/razvilka/internal/sources"
)

type sourceOfflineFile struct {
	Data     string
	Mode     fs.FileMode
	Modified time.Time
}

func sourceOfflineFiles(t *testing.T, root string) map[string]sourceOfflineFile {
	t.Helper()
	files := map[string]sourceOfflineFile{}
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		files[relative] = sourceOfflineFile{Data: string(data), Mode: info.Mode(), Modified: info.ModTime()}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return files
}

func sourceOfflineFixture(t *testing.T, kind string) (*App, string) {
	t.Helper()
	root := t.TempDir()
	cache := filepath.Join(root, "cache")
	src := sources.Source{ID: "saved", Name: "Saved", Kind: "domains", URL: "https://source.example/list",
		Enabled: true, MinEntries: 1, TTLHours: 1, Services: []string{"telegram"}}
	if kind == "reference" {
		src.Kind = "reference"
	}
	reg := sources.Registry{Schema: 2, Sources: []sources.Source{src}}
	settings := filepath.Join(root, "settings.json")
	m := sources.NewManager(reg, cache, settings)
	if kind == "fresh" || kind == "stale" || kind == "last-known-good" {
		m.SetHTTPClient(&http.Client{Transport: sourceFixtureTransport(func(req *http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": []string{"text/plain"}},
				Body: io.NopCloser(strings.NewReader("saved.example\n")), Request: req}, nil
		})})
		if err := m.Refresh(context.Background(), src.ID); err != nil {
			t.Fatal(err)
		}
	}
	if kind == "stale" {
		path := filepath.Join(cache, src.ID+".cache.json")
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var receipt map[string]json.RawMessage
		if err := json.Unmarshal(data, &receipt); err != nil {
			t.Fatal(err)
		}
		fetched := time.Now().UTC().Add(-2 * time.Hour)
		receipt["fetched_at"], _ = json.Marshal(fetched)
		receipt["expires_at"], _ = json.Marshal(fetched.Add(time.Hour))
		data, err = json.Marshal(receipt)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if kind == "legacy" || kind == "quarantined" {
		if err := os.MkdirAll(cache, 0o700); err != nil {
			t.Fatal(err)
		}
		name, body := src.ID+".lst", "saved.example\n"
		if kind == "quarantined" {
			name, body = src.ID+".cache.json", `{"schema":99}`
		}
		if err := os.WriteFile(filepath.Join(cache, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if kind == "stale" || kind == "legacy" || kind == "quarantined" {
		m = sources.NewManager(reg, cache, settings)
	}
	if kind == "last-known-good" {
		m.SetHTTPClient(&http.Client{Transport: sourceFixtureTransport(func(req *http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": []string{"text/html"}},
				Body: io.NopCloser(strings.NewReader("<html>rejected</html>")), Request: req}, nil
		})})
		if err := m.Refresh(context.Background(), src.ID); err == nil {
			t.Fatal("fixture failed to retain last-known-good receipt")
		}
	}
	if err := m.SetDraft(src.ID, false); err != nil {
		t.Fatal(err)
	}
	m.SetHTTPClient(&http.Client{Transport: sourceFixtureTransport(func(*http.Request) (*http.Response, error) {
		t.Error("offline GET attempted a source fetch")
		return nil, errors.New("fetch forbidden in offline fixture")
	})})
	return &App{Sources: m}, root
}

func TestSourceOfflineCatalogPreservesSavedStatesWithoutFetchOrWrites(t *testing.T) {
	for _, kind := range []string{"fresh", "stale", "legacy", "last-known-good", "quarantined", "missing", "reference"} {
		t.Run(kind, func(t *testing.T) {
			a, root := sourceOfflineFixture(t, kind)
			beforeFiles, beforeStates := sourceOfflineFiles(t, root), a.Sources.List()
			beforeReady := a.Sources.AutomaticUseReady([]string{"telegram"})
			for repeat := 0; repeat < 2; repeat++ {
				w := httptest.NewRecorder()
				a.sourceOfflineCatalog(w, httptest.NewRequest(http.MethodGet, sourceOfflineCatalogPath, nil))
				if w.Code != http.StatusOK || w.Header().Get("Cache-Control") != "no-store" ||
					w.Header().Get("Content-Type") != "application/json; charset=utf-8" {
					t.Fatalf("offline response: %d %v", w.Code, w.Header())
				}
				var view sourceOfflineCatalogView
				if err := json.Unmarshal(w.Body.Bytes(), &view); err != nil {
					t.Fatal(err)
				}
				if !view.Offline || !view.ReadOnly || len(view.Sources) != 1 {
					t.Fatal("missing read-only offline DTO")
				}
				row, saved := view.Sources[0], beforeStates[0]
				if !row.Offline || row.Ready || row.ID != saved.ID || row.Entries != saved.Entries || row.SHA256 != saved.SHA256 ||
					!row.UpdatedAt.Equal(saved.UpdatedAt) || !row.ExpiresAt.Equal(saved.ExpiresAt) || row.LegacyCache != saved.LegacyCache ||
					row.LastError != saved.LastError || !reflect.DeepEqual(row.Provenance, saved.Provenance) || !reflect.DeepEqual(row.Diff, saved.Diff) ||
					row.Enabled != saved.Enabled || row.AppliedEnabled != saved.AppliedEnabled || row.Dirty != saved.Dirty {
					t.Fatal("offline DTO promoted or changed saved source metadata")
				}
				if saved.Ready && (row.CacheStatus != "offline-cache" || !row.LastKnownGood) ||
					!saved.Ready && row.CacheStatus != saved.CacheStatus {
					t.Fatal("offline DTO lost cache state")
				}
			}
			if !reflect.DeepEqual(beforeFiles, sourceOfflineFiles(t, root)) || !reflect.DeepEqual(beforeStates, a.Sources.List()) ||
				beforeReady != a.Sources.AutomaticUseReady([]string{"telegram"}) {
				t.Fatal("offline GET changed files, settings, TTL or manager readiness")
			}
			legacy := httptest.NewRecorder()
			a.sourceList(legacy, httptest.NewRequest(http.MethodGet, "/api/v1/sources", nil))
			var live []sources.State
			if err := json.Unmarshal(legacy.Body.Bytes(), &live); err != nil || !reflect.DeepEqual(live, beforeStates) {
				t.Fatal("existing sourceList response changed")
			}
		})
	}
}

func TestSourceOfflineCatalogEmptyAndNonGET(t *testing.T) {
	a := &App{}
	w := httptest.NewRecorder()
	a.sourceOfflineCatalog(w, httptest.NewRequest(http.MethodGet, sourceOfflineCatalogPath, nil))
	if w.Code != http.StatusOK || strings.TrimSpace(w.Body.String()) != `{"offline":true,"read_only":true,"sources":[]}` {
		t.Fatal("empty catalogue is not an explicit read-only offline array")
	}
	a, root := sourceOfflineFixture(t, "fresh")
	before := sourceOfflineFiles(t, root)
	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodHead} {
		w := httptest.NewRecorder()
		a.sourceOfflineCatalog(w, httptest.NewRequest(method, sourceOfflineCatalogPath, strings.NewReader(`{"refresh":true}`)))
		if w.Code != http.StatusMethodNotAllowed || w.Header().Get("Allow") != http.MethodGet || w.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("non-GET accepted: %s %d", method, w.Code)
		}
	}
	if !reflect.DeepEqual(before, sourceOfflineFiles(t, root)) {
		t.Fatal("non-GET changed source files")
	}
}

func TestSourceOfflineCatalogUsesExistingAuthenticationAndRouteSpecificity(t *testing.T) {
	a, root := sourceOfflineFixture(t, "fresh")
	gate, err := security.NewGate(cloudflareTestToken)
	if err != nil {
		t.Fatal(err)
	}
	if err := gate.ConfigureCredentials(filepath.Join(root, "admin.json")); err != nil {
		t.Fatal(err)
	}
	session, err := gate.Setup("admin", "offline catalogue fixture password")
	if err != nil {
		t.Fatal(err)
	}
	a.Security = gate
	// CORE owns the one production mux registration. This fixture uses the
	// same handler/middleware chain without claiming that registration exists.
	mux := http.NewServeMux()
	mux.HandleFunc(sourceOfflineCatalogPath, a.sourceOfflineCatalog)
	mux.HandleFunc("/api/v1/sources", a.sourceList)
	mux.HandleFunc("/api/v1/sources/", a.sourceAction)
	handler := securityHeaders(a.auditMiddleware(gate.Middleware(a.operationMiddleware(mux))))
	cookies := httptest.NewRecorder()
	security.SetSessionCookie(cookies, httptest.NewRequest(http.MethodGet, "http://router.local", nil), session)
	cookie := cookies.Result().Cookies()[0]
	request := func(authenticated bool) *http.Request {
		r := httptest.NewRequest(http.MethodGet, "http://router.local"+sourceOfflineCatalogPath, nil)
		if authenticated {
			r.AddCookie(cookie)
		}
		return r
	}
	before := sourceOfflineFiles(t, root)
	for _, authenticated := range []bool{false, true} {
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, request(authenticated))
		want := http.StatusUnauthorized
		if authenticated {
			want = http.StatusOK
		}
		if w.Code != want || !authenticated && strings.Contains(w.Body.String(), "saved.example") {
			t.Fatalf("authentication or exact route changed: %d", w.Code)
		}
	}
	gate.Logout(request(true))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, request(true))
	if w.Code != http.StatusUnauthorized || !reflect.DeepEqual(before, sourceOfflineFiles(t, root)) {
		t.Fatal("logout fallback returned saved data or offline GET wrote files")
	}
}
