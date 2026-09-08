package sources

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func cachedFixture(t *testing.T) (*Manager, Source) {
	t.Helper()
	src := Source{ID: "example", Name: "Example", Kind: "domains", URL: "https://source.example/public-list", Enabled: true, MinEntries: 1, Services: []string{"telegram"}, TTLHours: 1, TrustTier: "community"}
	m := NewManager(Registry{Schema: 2, Sources: []Source{src}}, t.TempDir())
	m.SetHTTPClient(listClient("good.example\n", "text/plain"))
	if err := m.Refresh(context.Background(), src.ID); err != nil {
		t.Fatal(err)
	}
	return m, src
}

func listClient(body, contentType string) *http.Client {
	return &http.Client{Transport: fixtureTransport(func(req *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{contentType}}, Body: io.NopCloser(strings.NewReader(body)), Request: req}, nil
	})}
}

func TestSourceReceiptPinAndLastKnownGoodSurviveRestart(t *testing.T) {
	m, src := cachedFixture(t)
	before, err := os.ReadFile(filepath.Join(m.cacheDir, src.ID+".cache.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(before), "private-key") || strings.Contains(string(before), "private-value") {
		t.Fatal("cache receipt leaked URL secret")
	}
	state := m.List()[0]
	if !m.AutomaticUseReady([]string{"telegram"}) {
		t.Fatal("fresh receipt blocked automation")
	}
	if !state.Ready || state.Provenance == nil || !validDigest(state.Provenance.RawSHA256) || state.CacheStatus != "fresh" {
		t.Fatalf("missing receipt: %+v", state)
	}
	m.SetHTTPClient(listClient("<html>private-response.example</html>", "text/html"))
	if err := m.Refresh(context.Background(), src.ID); err == nil {
		t.Fatal("HTML accepted")
	}
	after, _ := os.ReadFile(filepath.Join(m.cacheDir, src.ID+".cache.json"))
	if string(before) != string(after) {
		t.Fatal("bad update replaced LKG")
	}
	q, _ := os.ReadFile(filepath.Join(m.cacheDir, src.ID+".quarantine.json"))
	if len(q) == 0 || strings.Contains(string(q), "private-") {
		t.Fatalf("unsafe quarantine: %s", q)
	}
	m.SetHTTPClient(listClient("<!doctype html>\nfalse-success.example\n", "text/plain"))
	if err := m.Refresh(context.Background(), src.ID); err == nil {
		t.Fatal("mislabeled HTML with a valid-looking domain accepted")
	}
	reloaded := NewManager(m.reg, m.cacheDir)
	state = reloaded.List()[0]
	if !state.Ready || !state.LastKnownGood || state.CacheStatus != "last-known-good" {
		t.Fatalf("LKG not restored: %+v", state)
	}
	pinned := src
	pinned.ExpectedSHA256 = contentHash([]byte("expected.example\n"))
	pinnedManager := NewManager(Registry{Sources: []Source{pinned}}, t.TempDir())
	pinnedManager.SetHTTPClient(listClient("different.example\n", "text/plain"))
	if err := pinnedManager.Refresh(context.Background(), src.ID); err == nil || !strings.Contains(err.Error(), "SHA256") {
		t.Fatalf("wrong pin accepted: %v", err)
	}
	pinnedManager.SetHTTPClient(listClient("expected.example\n", "text/plain"))
	if err := pinnedManager.Refresh(context.Background(), src.ID); err != nil {
		t.Fatal(err)
	}
}

func TestCacheTamperAndSourceReplacementDoNotFallBackToLegacy(t *testing.T) {
	for _, change := range []string{"content", "source", "expiry", "diff-count", "diff-hash"} {
		t.Run(change, func(t *testing.T) {
			m, src := cachedFixture(t)
			cached, err := m.readCache(src)
			if err != nil {
				t.Fatal(err)
			}
			switch change {
			case "content":
				cached.Content = "other.example\n"
			case "source":
				src.URL = "https://new.example/list"
			case "expiry":
				cached.ExpiresAt = cached.FetchedAt.Add(300 * time.Hour)
			case "diff-count":
				cached.Diff.Added = -1
			case "diff-hash":
				cached.Diff.PreviousSHA256 = "invalid"
			}
			data, _ := json.Marshal(cached)
			if err := os.WriteFile(filepath.Join(m.cacheDir, src.ID+".cache.json"), data, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(m.cacheDir, src.ID+".lst"), []byte("legacy.example\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			reloaded := NewManager(Registry{Sources: []Source{src}}, m.cacheDir)
			if reloaded.List()[0].Ready {
				t.Fatal("invalid receipt trusted or silently fell back to legacy")
			}
		})
	}
}

func TestSourceEntryLimitAndDiff(t *testing.T) {
	m, src := cachedFixture(t)
	first := m.List()[0]
	if first.Diff == nil || first.Diff.Added != 1 || first.Diff.Removed != 0 || first.Diff.PreviousSHA256 != "" {
		t.Fatalf("invalid first diff: %+v", first.Diff)
	}
	m.SetHTTPClient(listClient("new.example\nsecond.example\n", "text/plain"))
	if err := m.Refresh(context.Background(), src.ID); err != nil {
		t.Fatal(err)
	}
	state := NewManager(m.reg, m.cacheDir).List()[0]
	if state.Diff == nil || state.Diff.Added != 2 || state.Diff.Removed != 1 || state.Diff.PreviousSHA256 != first.SHA256 {
		t.Fatalf("diff not persisted: %+v", state.Diff)
	}
	if err := m.Refresh(context.Background(), src.ID); err != nil {
		t.Fatal(err)
	}
	if got := m.List()[0].Diff; got.Added != 0 || got.Removed != 0 {
		t.Fatalf("unchanged list: %+v", got)
	}
	if got := cacheDiff(cacheDocument{}, []string{"new.example"}); got.Added != 1 || got.Removed != 0 {
		t.Fatalf("empty previous list: %+v", got)
	}
	if _, err := validateLinesLimited("domains", "one.example\ntwo.example\n", 1); err == nil {
		t.Fatal("entry limit ignored")
	}
	if entries, err := validateLinesLimited("domains", "one.example\none.example\n", 1); err != nil || len(entries) != 1 {
		t.Fatalf("duplicate consumes budget: %v", err)
	}
	src.MaxEntries = 1
	limited := NewManager(Registry{Schema: 2, Sources: []Source{src}}, t.TempDir())
	limited.SetHTTPClient(listClient("one.example\n", "text/plain"))
	if err := limited.Refresh(context.Background(), src.ID); err != nil {
		t.Fatal(err)
	}
	limited.SetHTTPClient(listClient("one.example\ntwo.example\n", "text/plain"))
	if err := limited.Refresh(context.Background(), src.ID); err == nil {
		t.Fatal("oversized update accepted")
	}
	if got := limited.List()[0]; !got.LastKnownGood || got.Entries != 1 {
		t.Fatalf("entry limit replaced LKG: %+v", got)
	}
}

func TestSignedCDNRedirectSecretsAreNotPersisted(t *testing.T) {
	m, src := cachedFixture(t)
	m.reg.Sources[0].RedirectHosts = []string{"cdn.example"}
	calls := 0
	m.SetHTTPClient(&http.Client{Transport: fixtureTransport(func(req *http.Request) (*http.Response, error) {
		calls++
		if req.URL.Hostname() == "source.example" {
			return &http.Response{StatusCode: 302, Header: http.Header{"Location": []string{"https://cdn.example/private-path?signature=private-token"}}, Body: io.NopCloser(strings.NewReader("")), Request: req}, nil
		}
		return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{"text/plain"}}, Body: io.NopCloser(strings.NewReader("new.example\n")), Request: req}, nil
	})})
	if err := m.Refresh(context.Background(), src.ID); err != nil {
		t.Fatal(err)
	}
	if calls != 2 {
		t.Fatalf("redirect was not followed: %d", calls)
	}
	data, err := os.ReadFile(filepath.Join(m.cacheDir, src.ID+".cache.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "private-") || strings.Contains(string(data), "signature") {
		t.Fatal("signed URL leaked to receipt")
	}
	public, _ := json.Marshal(m.List())
	if strings.Contains(string(public), "private-") {
		t.Fatal("signed URL leaked to public state")
	}
	if m.List()[0].Provenance.FinalURL != "https://cdn.example/" {
		t.Fatal("redacted final origin lost")
	}
}

func TestExpiredSourceDoesNotEnrichNewPlans(t *testing.T) {
	m, src := cachedFixture(t)
	cached, err := m.readCache(src)
	if err != nil {
		t.Fatal(err)
	}
	cached.FetchedAt = time.Now().UTC().Add(-2 * time.Hour)
	cached.ExpiresAt = cached.FetchedAt.Add(sourceTTL(src))
	data, _ := json.Marshal(cached)
	if err := os.WriteFile(filepath.Join(m.cacheDir, src.ID+".cache.json"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	reloaded := NewManager(m.reg, m.cacheDir)
	state := reloaded.List()[0]
	if state.Ready || state.CacheStatus != "stale" {
		t.Fatalf("expired list presented as fresh: %+v", state)
	}
	if reloaded.AutomaticUseReady([]string{"telegram"}) {
		t.Fatal("stale enrichment allowed automatic route change")
	}
	if !reloaded.AutomaticUseReady([]string{"youtube"}) {
		t.Fatal("unused stale source blocked another service")
	}
	domains, _ := reloaded.EntriesForService("telegram")
	if len(domains) != 0 {
		t.Fatal("expired source enriched a new plan")
	}
	if _, err := os.Stat(filepath.Join(m.cacheDir, src.ID+".cache.json")); err != nil {
		t.Fatal("expired cache was destroyed")
	}
}

func TestLegacyRegistryRedirectMigrationIsNarrow(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sources.json")
	reg := Registry{Sources: []Source{
		{ID: "known", Name: "Known", Kind: "domains", URL: "https://github.com/1andrevich/Re-filter-lists/releases/latest/download/domains_all.lst"},
		{ID: "other", Name: "Other", Kind: "domains", URL: "https://github.com/unknown/source/releases/latest/download/list"},
	}}
	data, _ := json.Marshal(reg)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadRegistry(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded.Sources[0].RedirectHosts) != 2 || len(loaded.Sources[1].RedirectHosts) != 0 {
		t.Fatal("legacy migration granted excess redirect trust")
	}
}

func TestSourceQueueCancellationAndPrivateURLRejection(t *testing.T) {
	m, src := cachedFixture(t)
	m.refreshGate <- struct{}{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := m.Refresh(ctx, src.ID); !errors.Is(err, context.Canceled) {
		t.Fatalf("queue ignored cancellation: %v", err)
	}
	<-m.refreshGate
	for _, raw := range []string{"http://example.com/", "https://127.0.0.1/", "https://user:private@example.com/", "https://example.com:8443/", "https://example.com/list?token=private"} {
		s := src
		s.URL = raw
		rejected := NewManager(Registry{Sources: []Source{s}}, t.TempDir())
		rejected.SetHTTPClient(&http.Client{Transport: fixtureTransport(func(*http.Request) (*http.Response, error) {
			t.Fatal("unsafe request reached transport")
			return nil, nil
		})})
		if err := rejected.Refresh(context.Background(), src.ID); err == nil {
			t.Fatalf("unsafe source accepted: %s", raw)
		}
		data, _ := json.Marshal(rejected.List())
		if strings.Contains(string(data), "private") {
			t.Fatalf("credential leaked: %s", data)
		}
	}
}
