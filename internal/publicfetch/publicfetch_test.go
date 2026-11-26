package publicfetch

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"testing"
	"time"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

func TestURLAndAddressBoundary(t *testing.T) {
	for _, raw := range []string{
		"http://example.com/list", "file:///etc/passwd", "https://user:pass@example.com/list", "https://example.com/#secret",
		"https://example.com:8443/list", "https://localhost/", "https://router.lan/", "https://router.local/", "https://router.home.arpa/",
		"https://127.0.0.1/", "https://10.0.0.1/", "https://169.254.169.254/", "https://100.100.100.200/", "https://198.18.0.1/",
		"https://[::1]/", "https://[::ffff:127.0.0.1]/", "https://[fe80::1%25eth0]/", "https://[64:ff9b::a00:1]/",
		"https://[fc00::1]/", "https://2130706433/", "https://example..com/", "https://example.com.evil:80/",
	} {
		if ValidateURL(raw) == nil {
			t.Errorf("unsafe URL accepted: %s", raw)
		}
	}
	for _, raw := range []string{"https://example.com/list?token=private", "https://raw.githubusercontent.com/org/repo/list", "https://8.8.8.8:443/", "https://[2606:4700:4700::1111]/"} {
		if err := ValidateURL(raw); err != nil {
			t.Errorf("public URL rejected: %s %v", raw, err)
		}
	}
	for _, raw := range []string{"192.0.2.1", "198.51.100.1", "203.0.113.1", "224.0.0.1", "255.255.255.255", "2001:db8::1", "::", "100.64.0.1", "2002:7f00:1::"} {
		if PublicAddress(netip.MustParseAddr(raw)) {
			t.Errorf("special-use address accepted: %s", raw)
		}
	}
}

func TestDialRejectsAllPrivateAnswersAndPinsPublicIP(t *testing.T) {
	for _, answers := range [][]netip.Addr{
		{netip.MustParseAddr("127.0.0.1")},
		{netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("192.168.1.1")},
		{netip.MustParseAddr("8.8.8.8")},
	} {
		lookups, dials := 0, 0
		lookup := func(context.Context, string, string) ([]netip.Addr, error) {
			lookups++
			if lookups > 1 {
				return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
			}
			return answers, nil
		}
		dial := func(_ context.Context, _, address string) (net.Conn, error) {
			dials++
			if address != "8.8.8.8:443" {
				t.Fatalf("dial was not pinned: %s", address)
			}
			left, right := net.Pipe()
			_ = right.Close()
			return left, nil
		}
		conn, err := resolveAndDial(context.Background(), "tcp", "source.example:443", lookup, dial)
		if conn != nil {
			_ = conn.Close()
		}
		safe := len(answers) == 1 && answers[0].String() == "8.8.8.8"
		if safe && (err != nil || dials != 1) || !safe && (!errors.Is(err, ErrAddress) || dials != 0) || lookups != 1 {
			t.Fatalf("answers=%v dial=%d lookup=%d error=%v", answers, dials, lookups, err)
		}
	}
}

func TestRedirectPolicyPreventsRequestsAndScrubsHeaders(t *testing.T) {
	for _, target := range []string{"http://source.example/list", "https://127.0.0.1/secret", "https://untrusted.example/list", "https://cdn.example/list?signature=private"} {
		calls := 0
		base := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			calls++
			if calls == 1 {
				return &http.Response{StatusCode: 302, Header: http.Header{"Location": []string{target}}, Body: io.NopCloser(strings.NewReader(""))}, nil
			}
			for _, name := range []string{"Authorization", "Cookie", "Proxy-Authorization", "Referer"} {
				if req.Header.Get(name) != "" {
					t.Fatalf("redirect leaked header %s", name)
				}
			}
			return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("ok"))}, nil
		})}
		client := WithPolicy(base, "https://source.example/private-token", []string{"cdn.example"})
		req, _ := http.NewRequest(http.MethodGet, "https://source.example/private-token", nil)
		req.Header.Set("Authorization", "Bearer private")
		req.Header.Set("Cookie", "secret=value")
		req.Header.Set("Proxy-Authorization", "private")
		resp, err := client.Do(req)
		if resp != nil {
			_ = resp.Body.Close()
		}
		allowed := strings.HasPrefix(target, "https://cdn.example/")
		if allowed && (err != nil || calls != 2) || !allowed && (err == nil || calls != 1) {
			t.Fatalf("target=%s calls=%d error=%v", target, calls, err)
		}
	}
}

func TestTLSRemainsVerifiedWithoutEnvironmentProxy(t *testing.T) {
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1234")
	tr := transport()
	if tr.Proxy != nil || tr.TLSClientConfig.InsecureSkipVerify || tr.TLSClientConfig.MinVersion < tls.VersionTLS12 {
		t.Fatal("unsafe default transport")
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("untrusted TLS certificate was accepted") }))
	defer server.Close()
	tr.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", server.Listener.Addr().String())
	}
	defer tr.CloseIdleConnections()
	client := WithPolicy(&http.Client{Transport: tr}, "https://source.example/", nil)
	_, err := client.Get("https://source.example/private-token?secret=value")
	if err == nil || !strings.Contains(SafeError(err).Error(), "TLS") {
		t.Fatalf("TLS failure not classified: %v", err)
	}
}

func TestRedactionAndCancelledResolution(t *testing.T) {
	raw := "https://source.example/path-secret?token=secret"
	if RedactedURL(raw) != "https://source.example/" {
		t.Fatal("URL redaction failed")
	}
	var err error = &url.Error{Op: "Get", URL: raw, Err: errors.New("arbitrary private response")}
	if strings.Contains(SafeError(err).Error(), "secret") || strings.Contains(SafeError(err).Error(), "private") {
		t.Fatal("error leaked remote data")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	_, err = resolveAndDial(ctx, "tcp", "source.example:443", func(ctx context.Context, _, _ string) ([]netip.Addr, error) { <-ctx.Done(); return nil, ctx.Err() }, func(context.Context, string, string) (net.Conn, error) {
		t.Fatal("dial after cancellation")
		return nil, nil
	})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("got %v", err)
	}
}
