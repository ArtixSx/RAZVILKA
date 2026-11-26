package dnscontrol

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"reflect"
	"sync/atomic"
	"testing"
	"time"
)

func TestDoHNegotiatesHTTP2WithOriginalCertificateAndHost(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.ProtoMajor != 2 || r.Host != "example.com" || r.TLS.ServerName != "example.com" || r.Method != "POST" {
			t.Errorf("wrong request protocol/identity: %s %s %s %s", r.Proto, r.Host, r.TLS.ServerName, r.Method)
		}
		body, _ := io.ReadAll(r.Body)
		_, _ = w.Write(body)
	}))
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()
	for _, mode := range []string{"valid", "untrusted", "wrong-host"} {
		t.Run(mode, func(t *testing.T) {
			endpoint, _ := url.Parse("https://example.com/dns-query")
			if mode == "wrong-host" {
				endpoint.Host = "wrong.example"
			}
			tr, err := dohTransport(endpoint, []string{"1.1.1.1"}, false)
			if err != nil {
				t.Fatal(err)
			}
			defer tr.CloseIdleConnections()
			roots := x509.NewCertPool()
			if mode != "untrusted" {
				roots.AddCert(server.Certificate())
			}
			tr.TLSClientConfig.RootCAs = roots
			tr.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
			}
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			req, _ := http.NewRequestWithContext(ctx, "POST", endpoint.String(), bytes.NewReader([]byte("query")))
			resp, err := (&http.Client{Transport: tr}).Do(req)
			if mode != "valid" {
				if err == nil || serviceDNSErrorCode(err) != "DNS_TLS_FAILED" {
					t.Fatalf("certificate accepted: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			body, _ := io.ReadAll(resp.Body)
			if string(body) != "query" || resp.ProtoMajor != 2 {
				t.Fatalf("invalid response: %s %q", resp.Proto, body)
			}
		})
	}
	if calls.Load() != 1 {
		t.Fatalf("invalid TLS reached handler: %d", calls.Load())
	}
}

func TestDoHBootstrapIsBoundedAndDoesNotResolveOrChangeOrigin(t *testing.T) {
	ips := []netip.Addr{netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("2606:4700:4700::1111")}
	var attempted []string
	dial := func(ctx context.Context, network, address string) (net.Conn, error) {
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) > 2*time.Second || network != "tcp" {
			t.Fatal("unbounded/wrong network")
		}
		attempted = append(attempted, address)
		return nil, errors.New("unreachable")
	}
	_, err := dialDoHBootstrap(context.Background(), "tcp", "dns.example:443", "dns.example:443", ips, dial)
	if err == nil || !reflect.DeepEqual(attempted, []string{"1.1.1.1:443", "[2606:4700:4700::1111]:443"}) {
		t.Fatalf("bad targets: %v %v", attempted, err)
	}
	for _, target := range []string{"other.example:443", "dns.example:8443"} {
		_, err := dialDoHBootstrap(context.Background(), "tcp", target, "dns.example:443", ips, dial)
		if err == nil || len(attempted) != 2 {
			t.Fatal("origin expansion reached network")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = dialDoHBootstrap(ctx, "tcp", "dns.example:443", "dns.example:443", ips, dial)
	if !errors.Is(err, context.Canceled) || len(attempted) != 2 {
		t.Fatal("canceled request reached network")
	}
}

func TestDoHRejectsInvalidBootstrapBeforeIO(t *testing.T) {
	u, _ := url.Parse("https://dns.example/dns-query")
	for _, pins := range [][]string{{"127.0.0.1"}, {"1.1.1.1", "10.0.0.1"}, {"::ffff:1.1.1.1"}, {"2606:4700::1111%eth0"}, {"not-ip"}, {"1.1.1.1", "9.9.9.9", "8.8.8.8"}} {
		if _, err := dohTransport(u, pins, false); err == nil {
			t.Fatalf("accepted %v", pins)
		}
	}
	if len(dohBootstrapIPs("custom", "https://cloudflare-dns.com/dns-query")) != 0 || len(dohBootstrapIPs("cloudflare", "https://other.example/dns-query")) != 0 {
		t.Fatal("custom endpoint inherited pins")
	}
	provider, _ := providerByIDFor("cloudflare", document{})
	found := false
	for _, endpoint := range provider.Endpoints {
		if endpoint.Transport == "doh" {
			found = len(endpoint.BootstrapIPs) == 2
		}
	}
	if !found {
		t.Fatal("built-in provider missing reviewed bootstrap")
	}
}

func TestServiceDNSFailureCategoriesSurviveWrapping(t *testing.T) {
	for _, tc := range []struct {
		err  error
		code string
	}{
		{&net.DNSError{Err: "sensitive endpoint", IsTimeout: true}, "DNS_BOOTSTRAP_FAILED"},
		{&tls.CertificateVerificationError{Err: errors.New("private detail")}, "DNS_TLS_FAILED"},
		{dohStatusError(400), "DNS_HTTP_REJECTED"},
		{context.DeadlineExceeded, "DNS_QUERY_TIMEOUT"},
		{errDNSAnswer, "DNS_INTEGRITY_FAILED"},
		{errors.New("private detail"), "DNS_QUERY_FAILED"},
	} {
		if got := serviceDNSErrorCode(fmt.Errorf("wrapped: %w", tc.err)); got != tc.code {
			t.Fatalf("got %s want %s", got, tc.code)
		}
	}
}
