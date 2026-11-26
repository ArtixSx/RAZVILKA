package community

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"testing"
	"testing/iotest"

	"github.com/ArtixSx/razvilka/internal/publicfetch"
)

func telegramManager(t *testing.T) *Manager {
	t.Helper()
	m := budgetManager(t)
	m.registry.Entries[0].ID = "telegram-ip"
	m.registry.Entries[0].DomainsURL = ""
	m.registry.Entries[0].CIDRsURL = telegramCIDRsURL
	m.registry.Entries[0].SourcePage = telegramCIDRsURL
	return m
}

func offlineTelegram(m *Manager) {
	m.SetHTTPClient(&http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, &net.DNSError{Err: "unreachable", Name: "core.telegram.org", IsTimeout: true}
	})})
}

func TestTelegramBundledFallbackReviewAndRecovery(t *testing.T) {
	m := telegramManager(t)
	offlineTelegram(m)
	p, err := m.Preview(context.Background(), "telegram-ip", nil, true)
	if err != nil || !p.BundledFallback || p.SourceDate != "2026-10-20" || p.SourceURL != telegramCIDRsURL || p.FetchedAt != "2026-10-20T00:00:00Z" || len(p.Service.CIDRs) != 14 || len(p.Service.Domains) != 0 || p.Skipped != 0 || p.ImportGuard != "source-sha256" || len(p.SourceSHA) != 64 {
		t.Fatalf("invalid offline review: %+v %v", p, err)
	}
	if p.Service.Provenance.SHA256 != p.SourceSHA || p.Service.Provenance.FetchedAt != p.FetchedAt || !strings.Contains(p.Service.Note, "не свежая загрузка") {
		t.Fatal("offline provenance missing")
	}
	for _, raw := range p.Service.CIDRs {
		prefix := netip.MustParsePrefix(raw)
		if prefix.Bits() == 0 || !publicfetch.PublicPrefix(prefix) || raw == "95.161.64.0/20" {
			t.Fatalf("unexpected bundled network %s", raw)
		}
	}
	cached, err := m.Preview(context.Background(), "telegram-ip", nil, false)
	if err != nil || !cached.FromCache || !cached.BundledFallback || cached.SourceSHA != p.SourceSHA || cached.SourceDate != p.SourceDate {
		t.Fatal("cache lost bundled review")
	}
	m.SetHTTPClient(&http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(telegramSnapshot))}, nil
	})})
	live, err := m.Preview(context.Background(), "telegram-ip", nil, true)
	if err != nil || live.BundledFallback || live.SourceDate != "" || live.SourceSHA == p.SourceSHA || len(live.Service.CIDRs) != 14 {
		t.Fatalf("live source did not replace bundled review distinctly: %+v %v", live, err)
	}
}

func TestTelegramFallbackRefusesUnsafeFailures(t *testing.T) {
	for name, failure := range map[string]error{
		"TLS":     &tls.CertificateVerificationError{Err: x509.UnknownAuthorityError{}},
		"address": publicfetch.ErrAddress, "URL": publicfetch.ErrURL,
		"redirect": publicfetch.ErrRedirect, "redirectLimit": publicfetch.ErrRedirectLimit,
		"cancel": context.Canceled, "unknown": errors.New("unclassified failure"),
		"TLS record":  tls.RecordHeaderError{},
		"TLS timeout": context.DeadlineExceeded,
	} {
		t.Run(name, func(t *testing.T) {
			m := telegramManager(t)
			m.SetHTTPClient(&http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) { return nil, failure })})
			if p, err := m.Preview(context.Background(), "telegram-ip", nil, true); err == nil || p.ImportGuard != "" {
				t.Fatalf("unsafe failure became importable: %+v %v", p, err)
			}
		})
	}
	for _, body := range []string{"<html>blocked</html>", "not-a-network", "", "192.168.0.0/16", "0.0.0.0/0", strings.Repeat("91.108.56.0/22\n", maxSourceBytes/14+1)} {
		m := telegramManager(t)
		m.SetHTTPClient(&http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}, nil
		})})
		if p, err := m.Preview(context.Background(), "telegram-ip", nil, true); err == nil || p.BundledFallback {
			t.Fatalf("invalid source replaced by fallback: %q %+v %v", body, p, err)
		}
	}
	m := telegramManager(t)
	m.SetHTTPClient(&http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 503, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("unavailable"))}, nil
	})})
	if _, err := m.Preview(context.Background(), "telegram-ip", nil, true); err == nil {
		t.Fatal("HTTP failure became fallback")
	}
	m.SetHTTPClient(&http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(io.MultiReader(strings.NewReader(telegramSnapshot), iotest.ErrReader(errors.New("connection reset"))))}, nil
	})})
	if p, err := m.Preview(context.Background(), "telegram-ip", nil, true); err == nil || p.BundledFallback {
		t.Fatalf("body-read failure became fallback: %+v %v", p, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	offlineTelegram(m)
	if _, err := m.Preview(ctx, "telegram-ip", nil, true); !errors.Is(err, context.Canceled) {
		t.Fatalf("caller cancellation hidden: %v", err)
	}
}

func TestTelegramFallbackNetworkClassification(t *testing.T) {
	dial := &net.OpError{Op: "dial", Net: "tcp", Err: errors.New("connection refused")}
	for name, check := range map[string]struct {
		url  string
		err  error
		want bool
	}{
		"dial":            {telegramCIDRsURL, dial, true},
		"DNS":             {telegramCIDRsURL, &net.DNSError{Err: "no such host"}, true},
		"redirect target": {telegramCIDRsURL + "/redirected", dial, false},
		"read":            {telegramCIDRsURL, &net.OpError{Op: "read", Net: "tcp", Err: errors.New("reset")}, false},
	} {
		t.Run(name, func(t *testing.T) {
			if got := directNetworkFailure(context.Background(), telegramCIDRsURL, &url.Error{Op: "Get", URL: check.url, Err: check.err}); got != check.want {
				t.Fatalf("network classification = %v, want %v", got, check.want)
			}
		})
	}
}

func TestTelegramFallbackOnlyExactCuratedSource(t *testing.T) {
	for _, change := range []func(*Entry){
		func(e *Entry) { e.ID = "other" },
		func(e *Entry) { e.CIDRsURL += "?other" },
		func(e *Entry) { e.SourcePage = "https://github.com/example/source" },
		func(e *Entry) { e.DomainsURL = telegramCIDRsURL },
		func(e *Entry) { e.ListURL = telegramCIDRsURL },
	} {
		m := telegramManager(t)
		change(&m.registry.Entries[0])
		offlineTelegram(m)
		if p, err := m.Preview(context.Background(), m.registry.Entries[0].ID, nil, true); err == nil || p.BundledFallback {
			t.Fatalf("fallback escaped curated boundary: %+v %v", p, err)
		}
	}
}
