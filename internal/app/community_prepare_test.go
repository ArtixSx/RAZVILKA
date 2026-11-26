package app

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/community"
	"github.com/ArtixSx/razvilka/internal/customservices"
)

func communityPrepareFixture(t *testing.T) (*App, func(string, string, any) *httptest.ResponseRecorder) {
	t.Helper()
	a, send := awgAPITest(t)
	var err error
	a.Community, err = community.Load("../../configs/community-catalog.json")
	if err != nil {
		t.Fatal(err)
	}
	a.CustomServices, err = customservices.Load(filepath.Join(t.TempDir(), "custom.json"))
	if err != nil {
		t.Fatal(err)
	}
	return a, send
}

func TestCommunityPrepareReleasesAdmissionAndRevalidatesBeforePublication(t *testing.T) {
	for _, action := range []string{"preview", "import", "custom"} {
		for _, change := range []string{"none", "settings", "catalog", "busy", "fenced", "canceled"} {
			t.Run(action+"/"+change, func(t *testing.T) {
				a, send := communityPrepareFixture(t)
				response := func() *http.Response {
					return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{"text/plain"}}, Body: io.NopCloser(strings.NewReader("signal.org\n"))}
				}
				a.Community.SetHTTPClient(&http.Client{Transport: sourceFixtureTransport(func(*http.Request) (*http.Response, error) { return response(), nil })})
				base := send("GET", "/api/v1/community/services/signal/preview", nil)
				if base.Code != 200 {
					t.Fatal(base.Code, base.Body.String())
				}
				var preview community.Preview
				if json.Unmarshal(base.Body.Bytes(), &preview) != nil {
					t.Fatal("invalid preview")
				}
				started, unblock := make(chan struct{}), make(chan struct{})
				var once sync.Once
				releaseFetch := func() { once.Do(func() { close(unblock) }) }
				defer releaseFetch()
				a.Community.SetHTTPClient(&http.Client{Transport: sourceFixtureTransport(func(r *http.Request) (*http.Response, error) {
					close(started)
					select {
					case <-unblock:
						return response(), nil
					case <-r.Context().Done():
						return nil, r.Context().Err()
					}
				})})
				method, path, body := "GET", "/api/v1/community/services/signal/preview?refresh=true", any(nil)
				if action == "import" {
					method, path, body = "POST", "/api/v1/community/services/signal/import", map[string]any{"refresh": true, "expected_source_sha256": preview.SourceSHA}
				}
				if action == "custom" {
					method, path, body = "POST", "/api/v1/community/source-preview", map[string]any{"name": "Test", "format": "domains", "url": "https://raw.githubusercontent.com/example/repo/main/domains.txt", "expected_revision": a.Store.Get().Revision, "confirm": "PREVIEW_SERVICE_SOURCE"}
				}
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				req := autonomyRequest(method, path, body).WithContext(ctx)
				req.Header.Set("Authorization", "Bearer "+awgAPIToken)
				req.Header.Set("Content-Type", "application/json")
				w := httptest.NewRecorder()
				done := make(chan struct{})
				go func() { a.Handler(http.NotFoundHandler()).ServeHTTP(w, req); close(done) }()
				select {
				case <-started:
				case <-time.After(3 * time.Second):
					t.Fatal("fetch did not start")
				}
				// A real exclusive action can enter while the source is blocked.
				release, err := a.Operations.Exclusive(context.Background())
				if err != nil {
					t.Fatal("source retained network admission", err)
				}
				want := 200
				if action == "import" {
					want = 201
				}
				switch change {
				case "settings":
					if err := a.Store.SetSafeMode(!a.Store.Get().SafeMode); err != nil {
						t.Fatal(err)
					}
					want = 409
				case "catalog":
					a.Catalog.Services[0].Name += " changed"
					want = 409
				case "busy":
					want = 409
				case "fenced":
					a.Operations.Fence()
					want = 503
				case "canceled":
					cancel()
					want = 408
				}
				if change != "busy" {
					release()
				}
				defer release()
				releaseFetch()
				select {
				case <-done:
				case <-time.After(3 * time.Second):
					t.Fatal("request did not settle")
				}
				if w.Code != want {
					t.Fatalf("got %d want %d: %s", w.Code, want, w.Body.String())
				}
				if a.CustomServices.Has("custom-signal") != (action == "import" && change == "none") {
					t.Fatal("stale or missing import")
				}
				if a.communityPreparationCount.Load() != 0 {
					t.Fatal("preparation budget leaked")
				}
			})
		}
	}
}

func TestCommunityPrepareRequiresAuthAndBoundsConcurrentFetches(t *testing.T) {
	a, _ := communityPrepareFixture(t)
	req := autonomyRequest("GET", "/api/v1/community/services/signal/preview", nil)
	if _, err := a.beginCommunityPreparation(req); err != errCommunityAuth {
		t.Fatal("anonymous capture", err)
	}
	req.Header.Set("Authorization", "Bearer "+awgAPIToken)
	p1, err := a.beginCommunityPreparation(req)
	if err != nil {
		t.Fatal(err)
	}
	defer p1.close()
	p2, err := a.beginCommunityPreparation(req)
	if err != nil {
		t.Fatal(err)
	}
	defer p2.close()
	if _, err := a.beginCommunityPreparation(req); err == nil {
		t.Fatal("third parallel preparation accepted")
	}
	p1.close()
	p1.close()
	p3, err := a.beginCommunityPreparation(req)
	if err != nil {
		t.Fatal("budget not released", err)
	}
	p3.close()
	if a.communityPreparationCount.Load() != 1 {
		t.Fatal("duplicate release corrupted budget")
	}
}

func TestCommunityPreparedResponseRejectedAfterLogout(t *testing.T) {
	a, _ := communityPrepareFixture(t)
	if err := a.Security.ConfigureCredentials(filepath.Join(t.TempDir(), "admin.json")); err != nil {
		t.Fatal(err)
	}
	req := autonomyRequest("GET", "/api/v1/community/services/signal/preview", nil)
	session, err := a.Security.Setup("admin", "fixture-pass", req)
	if err != nil {
		t.Fatal(err)
	}
	req.AddCookie(&http.Cookie{Name: "razvilka_session", Value: session})
	p, err := a.beginCommunityPreparation(req)
	if err != nil {
		t.Fatal(err)
	}
	defer p.close()
	a.Security.Logout(req)
	if release, err := a.finishCommunityPreparation(context.Background(), req, p, true); err != errCommunityAuth {
		if release != nil {
			release()
		}
		t.Fatal("logout accepted", err)
	}
	if release, err := a.Operations.Exclusive(context.Background()); err != nil {
		t.Fatal("logout leaked admission", err)
	} else {
		release()
	}
}
