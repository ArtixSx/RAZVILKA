package sources

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestValidateDomainsRejectsTLDAndDeduplicates(t *testing.T) {
	got, err := validateLines("domains", "# comment\nexample.com\ncom\nEXAMPLE.com\ninvalid domain\nsub.example.org # x\n")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"example.com", "sub.example.org"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("got %v want %v", got, want)
	}
}

func TestValidateCIDRsRejectsPrivateAndDefault(t *testing.T) {
	got, err := validateLines("cidrs", "0.0.0.0/0\n10.0.0.0/8\n91.108.56.0/22\n2001:b28:f23d::/48\n")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"2001:b28:f23d::/48", "91.108.56.0/22"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("got %v want %v", got, want)
	}
}

func TestRefreshIsAtomicOnBadUpdate(t *testing.T) {
	good := true
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if good {
			_, _ = w.Write([]byte("a.example\nb.example\n"))
			return
		}
		_, _ = w.Write([]byte("com\ninvalid domain\n"))
	}))
	defer srv.Close()
	dir := t.TempDir()
	reg := Registry{Sources: []Source{{ID: "x", Name: "X", Kind: "domains", URL: srv.URL, Enabled: true, MinEntries: 2, MaxBytes: 4096}}}
	m := NewManager(reg, dir)
	if err := m.Refresh(context.Background(), "x"); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "x.lst")
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	good = false
	if err := m.Refresh(context.Background(), "x"); err == nil {
		t.Fatal("expected bad refresh to fail")
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatalf("cache changed after failed update: before=%q after=%q", before, after)
	}
}

func TestMaxBytes(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(strings.Repeat("a.example\n", 100)))
	}))
	defer srv.Close()
	reg := Registry{Sources: []Source{{ID: "x", Name: "X", Kind: "domains", URL: srv.URL, Enabled: true, MaxBytes: 20}}}
	m := NewManager(reg, t.TempDir())
	if err := m.Refresh(context.Background(), "x"); err == nil {
		t.Fatal("expected max_bytes error")
	}
}

func TestRegistryRejectsNonHTTPS(t *testing.T) {
	p := filepath.Join(t.TempDir(), "sources.json")
	if err := os.WriteFile(p, []byte(`{"sources":[{"id":"x","name":"X","kind":"domains","url":"http://example.com/x","enabled":true}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadRegistry(p); err == nil {
		t.Fatal("expected non-https source to be rejected")
	}
}

func TestReferenceSourceIsNotReportedAsReady(t *testing.T) {
	m := NewManager(Registry{Sources: []Source{{
		ID: "docs", Name: "Docs", Kind: "reference", URL: "https://example.com/docs", Enabled: true,
	}}}, t.TempDir())
	states := m.List()
	if len(states) != 1 || states[0].Ready {
		t.Fatalf("reference source must not count as a ready local list: %+v", states)
	}
}

func TestTamperedCacheIsRejectedOnStartup(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "x.lst"), []byte("valid.example\ncom\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	m := NewManager(Registry{Sources: []Source{{
		ID: "x", Name: "X", Kind: "domains", URL: "https://example.com/list", Enabled: true, MinEntries: 1,
	}}}, dir)
	states := m.List()
	if len(states) != 1 || states[0].Ready || !strings.Contains(states[0].LastError, "canonical") {
		t.Fatalf("tampered cache was trusted: %+v", states)
	}
}

func TestConcurrentRefreshLeavesOneCanonicalFile(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("b.example\na.example\n"))
	}))
	defer srv.Close()

	dir := t.TempDir()
	m := NewManager(Registry{Sources: []Source{{
		ID: "x", Name: "X", Kind: "domains", URL: srv.URL, Enabled: true, MinEntries: 2,
	}}}, dir)
	const workers = 12
	var wg sync.WaitGroup
	errs := make(chan error, workers)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- m.Refresh(context.Background(), "x")
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	b, err := os.ReadFile(filepath.Join(dir, "x.lst"))
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != "a.example\nb.example\n" {
		t.Fatalf("non-canonical final cache: %q", b)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "x.lst" {
		t.Fatalf("temporary cache files leaked: %+v", entries)
	}
}

func TestHTTPSRedirectCannotDowngrade(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://127.0.0.1/private", http.StatusFound)
	}))
	defer srv.Close()
	m := NewManager(Registry{Sources: []Source{{
		ID: "x", Name: "X", Kind: "domains", URL: srv.URL, Enabled: true,
	}}}, t.TempDir())
	m.SetHTTPClient(srv.Client())
	err := m.Refresh(context.Background(), "x")
	if err == nil || !strings.Contains(strings.ToLower(err.Error()), "https") {
		t.Fatalf("downgrade redirect was not rejected: %v", err)
	}
}

func TestRegistryRejectsUnsafeSourceID(t *testing.T) {
	p := filepath.Join(t.TempDir(), "sources.json")
	if err := os.WriteFile(p, []byte(`{"sources":[{"id":"../escape","name":"X","kind":"domains","url":"https://example.com/x","enabled":true}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadRegistry(p); err == nil {
		t.Fatal("expected unsafe source id to be rejected")
	}
}
