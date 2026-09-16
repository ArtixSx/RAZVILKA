package community

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

func customFixture(t *testing.T) *Manager {
	t.Helper()
	m, e := New(Registry{Schema: 1, Entries: []Entry{{ID: "fixture", Name: "Fixture", Category: "Test", Provider: "Test", SourcePage: "https://github.com/example/lists", DomainsURL: "https://raw.githubusercontent.com/example/lists/main/data", Access: Access{Status: "catalog", Note: "Test"}}}})
	if e != nil {
		t.Fatal(e)
	}
	return m
}
func TestRepair2CustomURLs(t *testing.T) {
	good := "https://github.com/example/lists/blob/main/test.list"
	got, e := GitHubSourceURL(good)
	if e != nil || got != "https://raw.githubusercontent.com/example/lists/main/test.list" {
		t.Fatal(got, e)
	}
	for _, u := range []string{"http://github.com/a/b/blob/main/x", "https://github.com.evil.test/a/b/blob/main/x", "https://user:pass@github.com/a/b/blob/main/x", "https://github.com/a/b", "https://github.com/a/b/blob/main/x?token=private", "https://127.0.0.1/a/b/main/x", "https://github.com/a/b/blob/main/../x", "https://github.com/a/b/blob/main/%2e%2e/x"} {
		t.Run(u, func(t *testing.T) {
			if _, e := GitHubSourceURL(u); e == nil {
				t.Fatal("unsafe URL accepted")
			}
		})
	}
}
func TestRepair2CustomPreviewHasBoundedReviewNotRouteAuthority(t *testing.T) {
	m := customFixture(t)
	x := CustomSource{Name: "Example", Format: "domains", Content: "example.org\nfull:cdn.example.org\nprinter.local\n", ProbeURL: "https://example.org/"}
	v, e := m.PreviewCustom(context.Background(), x, nil)
	if e != nil || v.ImportGuard != "source-sha256" || len(v.SourceSHA) != 64 || len(v.Service.Domains) != 2 || v.Skipped != 1 {
		t.Fatal(e, v)
	}
	again, e := m.Preview(context.Background(), v.Entry.ID, nil, false)
	if e != nil || !again.FromCache || again.SourceSHA != v.SourceSHA {
		t.Fatal(e)
	}
	again.Service.Domains[0] = "mutated.example"
	if next, _ := m.Preview(context.Background(), v.Entry.ID, nil, false); next.Service.Domains[0] == "mutated.example" {
		t.Fatal("alias")
	}
	m.mu.Lock()
	c := m.cache[v.Entry.ID]
	c.at = time.Now().Add(-11 * time.Minute)
	m.cache[v.Entry.ID] = c
	m.mu.Unlock()
	if _, e = m.Preview(context.Background(), v.Entry.ID, nil, false); !errors.Is(e, ErrPreviewExpired) {
		t.Fatal("expired review accepted", e)
	}
}
func TestRepair2CustomInputRejectsUnsafeAndOversized(t *testing.T) {
	for _, kind := range []string{"empty", "both", "private", "html", "large", "probe-other", "probe-ip", "probe-secret", "format"} {
		t.Run(kind, func(t *testing.T) {
			m := customFixture(t)
			x := CustomSource{Name: "Example", Format: "domains", Content: "example.org"}
			switch kind {
			case "empty":
				x.Content = ""
			case "both":
				x.URL = "https://github.com/a/b/blob/main/x"
			case "private":
				x.Content = "host.local\n127.0.0.1"
			case "html":
				x.Content = "<!doctype html><html>"
			case "large":
				x.Content = strings.Repeat("a", maxCustomSourceBytes+1)
			case "probe-other":
				x.ProbeURL = "https://other.example/"
			case "probe-ip":
				x.ProbeURL = "https://127.0.0.1/"
			case "probe-secret":
				x.ProbeURL = "https://example.org/?token=secret"
			case "format":
				x.Format = "shell"
			}
			if _, e := m.PreviewCustom(context.Background(), x, nil); e == nil {
				t.Fatal("unsafe input accepted")
			}
		})
	}
}
func TestRepair2CustomCacheAndBuiltinContract(t *testing.T) {
	m := customFixture(t)
	m.SetHTTPClient(&http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("example.org\n"))}, nil
	})})
	v, e := m.Preview(context.Background(), "fixture", nil, false)
	if e != nil || v.ImportGuard != "source-sha256" {
		t.Fatal("builtin backend contract", e, v)
	}
	for i := 0; i < 20; i++ {
		if _, e := m.PreviewCustom(context.Background(), CustomSource{Name: fmt.Sprint("Source", i), Format: "domains", Content: "example.org"}, nil); e != nil {
			t.Fatal(e)
		}
	}
	if len(m.cache) != maxCustomPreviews+1 {
		t.Fatal("unbounded adhoc cache", len(m.cache))
	}
}
