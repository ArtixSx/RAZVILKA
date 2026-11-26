package routeprobe

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/probecheck"
)

func TestDNSAddressProbePinsAddressAndKeepsVerifiedSNI(t *testing.T) {
	var requests atomic.Int32
	names := make(chan string, 4)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.Host != "example.com" || r.URL.Path != "/health" || r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" {
			t.Error("changed request identity or credentials", r.Host, r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"service":"fixture"}`)
	}))
	server.TLS = &tls.Config{GetConfigForClient: func(h *tls.ClientHelloInfo) (*tls.Config, error) { names <- h.ServerName; return nil, nil }}
	server.StartTLS()
	defer server.Close()
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	service := catalog.Service{ID: "fixture", ProbeURL: "https://example.com/health"}
	service.Probes = []catalog.Probe{{ID: "health", URL: service.ProbeURL, Expect: catalog.ProbeExpectation{JSON: true, JSONFields: []string{"service"}}}}
	// An environment proxy must never receive the request.
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	var dials atomic.Int32
	for _, pin := range []string{"1.1.1.1", "2606:4700:4700::1111"} {
		address := netip.MustParseAddr(pin)
		dial := func(ctx context.Context, network, target string) (net.Conn, error) {
			dials.Add(1)
			want := "tcp4"
			if address.Is6() {
				want = "tcp6"
			}
			if network != want || target != net.JoinHostPort(pin, "443") {
				t.Errorf("unexpected dial %s %s", network, target)
			}
			return (&net.Dialer{}).DialContext(ctx, "tcp", server.Listener.Addr().String())
		}
		got := probeDNSAddress(context.Background(), service, address, dial, roots)
		if !got.TLSVerified || !got.ServiceVerified || got.RouteVerified || got.Status != "pass" || got.BytesRead == 0 || got.TTFBMS < 0 {
			t.Fatalf("unexpected observation %+v", got)
		}
		if name := <-names; name != "example.com" {
			t.Fatal("SNI changed", name)
		}
	}
	if requests.Load() != 2 || dials.Load() != 2 {
		t.Fatal("candidates shared a connection or retried", requests.Load(), dials.Load())
	}
}

func TestDNSAddressProbeRejectsWrongTLSAndBlockPagesAndRedirects(t *testing.T) {
	for _, mode := range []string{"untrusted", "wrong-name", "block", "redirect", "oversized-json"} {
		t.Run(mode, func(t *testing.T) {
			var requests atomic.Int32
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				switch mode {
				case "block":
					w.WriteHeader(403)
					io.WriteString(w, "blocked")
				case "redirect":
					w.Header().Set("Location", "https://other.example/final")
					w.WriteHeader(302)
				case "oversized-json":
					w.Header().Set("Content-Type", "application/json")
					io.WriteString(w, `{"value":"`+strings.Repeat("x", 40000)+`"}`)
				default:
					io.WriteString(w, "ok")
				}
			}))
			server.Config.ErrorLog = log.New(io.Discard, "", 0)
			server.StartTLS()
			defer server.Close()
			roots := x509.NewCertPool()
			if mode != "untrusted" {
				roots.AddCert(server.Certificate())
			}
			service := catalog.Service{ID: "fixture", ProbeURL: "https://example.com/"}
			if mode == "wrong-name" {
				service.ProbeURL = "https://wrong.example/"
			}
			if mode == "oversized-json" {
				p := probecheck.ServiceProbe(service)
				p.Expect.JSON = true
				service.Probes = []catalog.Probe{p}
			}
			dial := func(ctx context.Context, network, target string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "tcp", server.Listener.Addr().String())
			}
			got := probeDNSAddress(context.Background(), service, netip.MustParseAddr("1.1.1.1"), dial, roots)
			if got.ServiceVerified || got.RouteVerified || got.Status == "pass" || got.BytesRead > probecheck.MaxBodyBytes {
				t.Fatalf("false positive %+v", got)
			}
			if mode == "untrusted" || mode == "wrong-name" {
				if requests.Load() != 0 || got.TLSVerified || got.ErrorCode != "DNS_ADDRESS_TLS_FAILED" {
					t.Fatalf("TLS bypass %+v", got)
				}
			} else if requests.Load() != 1 {
				t.Fatal("redirect or fallback requested")
			}
		})
	}
}

func TestDNSAddressProbeNoPrivateTargetsAndCancellation(t *testing.T) {
	calls := 0
	dial := func(ctx context.Context, _, _ string) (net.Conn, error) { calls++; <-ctx.Done(); return nil, ctx.Err() }
	service := catalog.Service{ID: "fixture", ProbeURL: "https://example.com/"}
	for _, pin := range []string{"127.0.0.1", "192.168.1.1", "::1", "::ffff:1.1.1.1", "169.254.169.254"} {
		if got := probeDNSAddress(context.Background(), service, netip.MustParseAddr(pin), dial, nil); got.ErrorCode != "DNS_ADDRESS_PROBE_INVALID" {
			t.Fatal(got)
		}
	}
	if calls != 0 {
		t.Fatal("private target dialed")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	start := time.Now()
	got := probeDNSAddress(ctx, service, netip.MustParseAddr("1.1.1.1"), dial, nil)
	if got.ServiceVerified || got.ErrorCode != "DNS_ADDRESS_TIMEOUT" || time.Since(start) > time.Second {
		t.Fatal("unbounded cancellation", got)
	}
}
