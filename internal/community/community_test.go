package community

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/ArtixSx/razvilka/internal/catalog"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) { return f(request) }

func TestPreviewParsesSourcesAndFindsConflicts(t *testing.T) {
	manager, err := New(Registry{Schema: 1, Entries: []Entry{{
		ID: "video", Name: "Video", Category: "Видео", Icon: "VI", Provider: "Test", License: "MIT",
		Access:     Access{Region: "RU", Status: "variable", Note: "Доступность зависит от сети."},
		SourcePage: "https://github.com/v2fly/domain-list-community",
		DomainsURL: "https://raw.githubusercontent.com/v2fly/domain-list-community/master/data/video",
		CIDRsURL:   "https://raw.githubusercontent.com/Loyalsoldier/geoip/release/clash/ipcidr/video.txt",
		ProbeURL:   "https://video.example/",
	}}})
	if err != nil {
		t.Fatal(err)
	}
	manager.SetHTTPClient(&http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		body := "video.example\nfull:cdn.video.example\nregexp:.*\\.invalid\ninclude:other\n"
		if strings.Contains(request.URL.Path, "ipcidr") {
			body = "payload:\n  - '203.0.113.0/24'\n  - IP-CIDR,198.51.100.0/24,no-resolve\n  - 192.168.0.0/16\n"
		}
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
	})})

	preview, err := manager.Preview(context.Background(), "video", []catalog.Service{{ID: "existing", Name: "Existing", Domains: []string{"video.example"}}}, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(preview.Service.Domains) != 2 || len(preview.Service.CIDRs) != 2 {
		t.Fatalf("unexpected parsed service: %+v", preview.Service)
	}
	if preview.Skipped != 3 {
		t.Fatalf("skipped=%d, want 3", preview.Skipped)
	}
	if len(preview.Conflicts) != 1 || preview.Conflicts[0].Value != "video.example" {
		t.Fatalf("unexpected conflicts: %+v", preview.Conflicts)
	}
	selfPreview, err := manager.Preview(context.Background(), "video", []catalog.Service{{ID: "custom-video", Name: "Video", Domains: []string{"video.example"}}}, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(selfPreview.Conflicts) != 0 {
		t.Fatalf("imported service must not conflict with itself: %+v", selfPreview.Conflicts)
	}
	if preview.Service.Provenance == nil || len(preview.Service.Provenance.SHA256) != 64 {
		t.Fatalf("missing provenance: %+v", preview.Service.Provenance)
	}

	cached, err := manager.Preview(context.Background(), "video", nil, false)
	if err != nil || !cached.FromCache {
		t.Fatalf("cached preview: from_cache=%v err=%v", cached.FromCache, err)
	}
}

func TestRegistryRejectsUntrustedSource(t *testing.T) {
	_, err := New(Registry{Schema: 1, Entries: []Entry{{
		ID: "unsafe", Name: "Unsafe", Category: "Test", Provider: "Test",
		Access:     Access{Region: "RU", Status: "catalog", Note: "Тест."},
		SourcePage: "https://example.com/", DomainsURL: "https://192.168.1.1/domains",
	}}})
	if err == nil {
		t.Fatal("expected untrusted source rejection")
	}
}

func TestSearchAliasesAndImportedState(t *testing.T) {
	manager, err := New(Registry{Schema: 1, Entries: []Entry{{
		ID: "signal", Name: "Signal", Aliases: []string{"сигнал"}, Category: "Мессенджеры", Provider: "Test",
		Access:     Access{Region: "RU", Status: "blocked", Note: "Ограничен."},
		SourcePage: "https://example.com/", DomainsURL: "https://raw.githubusercontent.com/v2fly/domain-list-community/master/data/signal",
	}}})
	if err != nil {
		t.Fatal(err)
	}
	result := manager.Search("сигнал", func(id string) bool { return id == "custom-signal" })
	if len(result) != 1 || !result[0].Imported {
		t.Fatalf("unexpected search result: %+v", result)
	}
}

func TestRegistryRejectsUnclassifiedAccess(t *testing.T) {
	_, err := New(Registry{Schema: 1, Entries: []Entry{{
		ID: "unknown", Name: "Unknown", Category: "Test", Provider: "Test", SourcePage: "https://example.com/",
		DomainsURL: "https://raw.githubusercontent.com/v2fly/domain-list-community/master/data/example",
	}}})
	if err == nil {
		t.Fatal("expected missing access status rejection")
	}
}
