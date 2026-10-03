package community

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// A transport to the local fixture never changes the allowlisted source URL.
type checkpointTransport struct {
	handler func(*http.Request) (*http.Response, error)
}

func (t checkpointTransport) RoundTrip(r *http.Request) (*http.Response, error) { return t.handler(r) }
func TestResearchGeoIndexSurvivesRestartAndOffline(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "community.json")
	registry := Registry{Schema: 1, Entries: []Entry{{ID: "local", Name: "Local", Category: "Test", Provider: "Test", SourcePage: "https://github.com/example/repo", DomainsURL: "https://raw.githubusercontent.com/example/repo/main/domains.txt", Access: Access{Region: "RU", Status: "catalog", Note: "Fixture"}}}}
	b, _ := json.Marshal(registry)
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	m, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	body := `{"version":1,"base":"` + geoAggregatorBase + `","categories":[{"id":"test","name":"Test"}],"services":[{"id":"offline","name":"Offline","cat":"test","src":"source1/offline.txt"}]}`
	var calls atomic.Int32
	m.SetHTTPClient(&http.Client{Transport: checkpointTransport{handler: func(r *http.Request) (*http.Response, error) {
		calls.Add(1)
		w := httptest.NewRecorder()
		w.WriteString(body)
		return w.Result(), nil
	}}})
	if err := m.RefreshGeoAggregator(context.Background()); err != nil {
		t.Fatal(err)
	}
	before := m.GeoAggregatorCacheStatus()
	if !before.Available || before.Stale {
		t.Fatal(before)
	}
	m2, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	m2.SetHTTPClient(&http.Client{Transport: checkpointTransport{handler: func(*http.Request) (*http.Response, error) {
		t.Fatal("fresh saved index triggered HTTP")
		return nil, nil
	}}})
	if err = m2.RefreshGeoAggregator(context.Background()); err != nil {
		t.Fatal(err)
	}
	after := m2.GeoAggregatorCacheStatus()
	if !after.CapturedAt.Equal(before.CapturedAt) || calls.Load() != 1 {
		t.Fatal("freshness was renewed on restart")
	}
	found := false
	for _, s := range m2.Search("offline", nil) {
		if s.ID == "ga-offline" {
			found = true
		}
	}
	if !found {
		t.Fatal("offline entry lost")
	}
	// A corrupted checkpoint is discarded without losing the curated registry.
	if err = os.WriteFile(filepath.Join(dir, geoCheckpointName), []byte(`{"schema":999}`), 0o600); err != nil {
		t.Fatal(err)
	}
	m3, err := Load(path)
	if err != nil || len(m3.Search("local", nil)) != 1 || m3.GeoAggregatorCacheStatus().Available {
		t.Fatal("bad cache breaks curated registry", err)
	}
}
func TestResearchGeoIndexRejectsTrailingJSON(t *testing.T) {
	raw := `{"version":1,"base":"` + geoAggregatorBase + `","categories":[{"id":"test","name":"Test"}],"services":[{"id":"ok","name":"OK","cat":"test","src":"source1/ok.txt"}]}`
	if _, err := geoEntries([]byte(raw + ` {}`)); err == nil {
		t.Fatal("trailing document accepted")
	}
	if _, err := geoEntries([]byte(strings.Repeat(" ", maxSourceBytes+1))); err == nil {
		t.Fatal("oversize index accepted")
	}
}
func TestResearchGeoRefreshSingleFlightAndCooldown(t *testing.T) {
	m := &Manager{cache: map[string]cachedPreview{}}
	var calls atomic.Int32
	entered, release := make(chan struct{}), make(chan struct{})
	m.SetHTTPClient(&http.Client{Transport: checkpointTransport{handler: func(r *http.Request) (*http.Response, error) {
		calls.Add(1)
		close(entered)
		<-release
		w := httptest.NewRecorder()
		w.WriteHeader(503)
		return w.Result(), nil
	}}})
	done := make(chan error, 1)
	go func() { done <- m.RefreshGeoAggregator(context.Background()) }()
	<-entered
	m.mu.Lock()
	m.geo = []Entry{{ID: "ga-old"}}
	m.geoAt = time.Now().Add(-24 * time.Hour)
	m.mu.Unlock()
	c, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if err := m.RefreshGeoAggregator(c); err != nil {
		t.Fatal("LKG reader waited", err)
	}
	close(release)
	if err := <-done; err == nil {
		t.Fatal("503 accepted")
	}
	if err := m.RefreshGeoAggregator(context.Background()); err == nil {
		t.Fatal("failed refresh not in cooldown")
	}
	if calls.Load() != 1 || !m.GeoAggregatorCacheStatus().Available {
		t.Fatal("stampede or lost LKG")
	}
}
