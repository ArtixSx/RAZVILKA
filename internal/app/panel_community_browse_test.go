package app

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/community"
)

func communityBrowseFixture(t *testing.T) *App {
	t.Helper()
	m, err := community.New(community.Registry{Schema: 1, Entries: []community.Entry{{ID: "display", Name: "Display", Category: "Test", Description: "Saved description", Provider: "Provider", SourcePage: "https://example.com/", DomainsURL: "https://raw.githubusercontent.com/example/list/main/data", Access: community.Access{Region: "RU", Status: "blocked", Note: "Not runtime proof"}}}})
	if err != nil {
		t.Fatal(err)
	}
	m.SetHTTPClient(&http.Client{Transport: sourceFixtureTransport(func(*http.Request) (*http.Response, error) {
		t.Fatal("saved publication attempted network refresh")
		return nil, nil
	})})
	a := savedPanelFixture(t)
	a.Community = m
	return a
}

func TestPanelCommunityBrowseBoundedDetachedProjectionAndLifecycle(t *testing.T) {
	a := communityBrowseFixture(t)
	now := time.Now()
	if !a.publishPanelCommunityBrowse(context.Background(), strings.Repeat("a", 32), now) {
		t.Fatal("memory projection unavailable")
	}
	first := a.panelSnapshots.community.Load()
	base := a.Community.Search("", nil)[0].Entry // Test setup only, never publisher.
	large := community.Registry{Schema: 1}
	for i := 0; i < 12; i++ {
		entry := base
		entry.ID, entry.Description = fmt.Sprintf("large-%d", i), strings.Repeat("<", 4096)
		large.Entries = append(large.Entries, entry)
	}
	oversized, err := community.New(large)
	if err != nil {
		t.Fatal(err)
	}
	originalManager := a.Community
	a.Community = oversized
	if a.publishPanelCommunityBrowse(context.Background(), "other", now) || a.panelSnapshots.community.Load() != first {
		t.Fatal("escaped encoded bytes exceeded the cap and replaced valid image")
	}
	a.Community = originalManager
	var data map[string][]map[string]any
	if json.Unmarshal(first.Data, &data) != nil || len(data["entries"]) != 1 {
		t.Fatal("missing display metadata")
	}
	allowed := map[string]bool{"id": true, "name": true, "category": true, "description": true}
	for key := range data["entries"][0] {
		if !allowed[key] {
			t.Fatal("proof, source or action field exposed", key)
		}
	}
	for _, tc := range []struct {
		age   time.Duration
		state string
		data  bool
	}{{0, "available", true}, {10 * time.Second, "retained", true}, {15 * time.Minute, "expired", false}, {-2 * time.Second, "expired", false}} {
		value := a.panelCommunityBrowseAt(now.Add(tc.age))
		if value.State != tc.state || (len(value.Data) > 0) != tc.data || value.MaxAgeSeconds != 900 || value.Dataplane != "not-checked" {
			t.Fatal("capture freshness contract changed", value)
		}
	}
	release, _ := a.Operations.Exclusive(context.Background())
	if a.publishPanelCommunityBrowse(context.Background(), "other", now) || a.panelCommunityBrowseAt(now).State != "retained" || a.panelSnapshots.community.Load() != first {
		t.Fatal("busy replaced saved definition")
	}
	release()
	a.Community = nil
	if a.publishPanelCommunityBrowse(context.Background(), "other", now) || a.panelSnapshots.community.Load() != first {
		t.Fatal("missing manager claimed an empty catalog")
	}
	a.Operations.FenceJournal()
	if a.publishPanelCommunityBrowse(context.Background(), "other", now) || a.panelCommunityBrowseAt(now).State != "retained" {
		t.Fatal("fenced publication changed")
	}
	empty := (&App{}).panelCommunityBrowseAt(now)
	if empty.State != "empty" || empty.GeneratedAt != nil || empty.Data != nil {
		t.Fatal("missing publication became authoritative empty")
	}
	// Independent normal startup/wake publication, no live search or refresh.
	b := communityBrowseFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	b.StartPanelSnapshots(ctx)
	if b.panelCommunityBrowseAt(time.Now()).Revision != 1 {
		t.Fatal("startup did not seed community")
	}
	deadline := time.Now().Add(time.Second)
	for b.panelCommunityBrowseAt(time.Now()).Revision < 2 && time.Now().Before(deadline) {
		b.wakePanelSnapshot()
		time.Sleep(time.Millisecond)
	}
	if b.panelCommunityBrowseAt(time.Now()).Revision < 2 {
		t.Fatal("wake did not publish")
	}
	cancel()
	stop, stopCancel := context.WithTimeout(context.Background(), time.Second)
	defer stopCancel()
	if err := b.WaitPanelSnapshots(stop); err != nil {
		t.Fatal(err)
	}
}

func TestPanelCommunityBrowseHTTPDoesNotReleaseLiveAdmission(t *testing.T) {
	a := communityBrowseFixture(t)
	a.publishPanelCommunityBrowse(context.Background(), strings.Repeat("b", 32), time.Now())
	original := bytes.Clone(a.panelSnapshots.community.Load().Data)
	a.Community, a.CustomServices, a.Store = nil, nil, nil
	release, _ := a.Operations.Exclusive(context.Background())
	defer release()
	server := httptest.NewServer(a.Handler(http.NotFoundHandler()))
	defer server.Close()
	client := &http.Client{Timeout: time.Second}
	for _, fenced := range []bool{false, true} {
		if fenced {
			a.Operations.FenceJournal()
		}
		for _, method := range []string{"GET", "HEAD", "POST"} {
			for _, auth := range []bool{false, true} {
				r, _ := http.NewRequest(method, server.URL+panelCommunityBrowsePath, nil)
				r.Header.Set("Content-Type", "application/json")
				if auth {
					r.Header.Set("Authorization", "Bearer "+panelTestToken)
				}
				response, err := client.Do(r)
				if err != nil {
					t.Fatal(err)
				}
				body, _ := io.ReadAll(response.Body)
				response.Body.Close()
				want := 200
				if method == "POST" {
					want = 405
				}
				if !auth {
					want = 401
				}
				if response.StatusCode != want || response.Header.Get("Cache-Control") != "no-store" {
					t.Fatal(method, auth, response.StatusCode)
				}
				if method == "HEAD" && len(body) > 0 {
					t.Fatal("HEAD returned body")
				}
				if method == "GET" && auth {
					var value panelDeviceBrowseResponse
					if json.Unmarshal(body, &value) != nil || value.State != "retained" || !bytes.Equal(value.Data, original) {
						t.Fatal("HTTP did not use original immutable bytes")
					}
				}
			}
		}
		for _, path := range []string{"/api/v1/community/services", panelCommunityBrowsePath + "/", panelCommunityBrowsePath + "/extra"} {
			w := httptest.NewRecorder()
			a.Handler(http.NotFoundHandler()).ServeHTTP(w, panelTestRequest("GET", path))
			want := 409
			if fenced {
				want = 503
			}
			if w.Code != want {
				t.Fatal("live/alias admission bypass", path, w.Code)
			}
		}
		if s := a.Operations.Snapshot(); !s.Exclusive || s.Active != 1 {
			t.Fatal("browse released original owner")
		}
	}
	r := panelTestRequest("POST", panelCommunityBrowsePath)
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Origin", "https://foreign.invalid")
	w := httptest.NewRecorder()
	a.Handler(http.NotFoundHandler()).ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatal("CSRF bypass")
	}
	a.Security = nil
	w = httptest.NewRecorder()
	a.operationMiddleware(http.NotFoundHandler()).ServeHTTP(w, httptest.NewRequest("GET", panelCommunityBrowsePath, nil))
	if w.Code != http.StatusUnauthorized {
		t.Fatal("missing auth exposed cached metadata")
	}
}
