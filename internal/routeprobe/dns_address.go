package routeprobe

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/probecheck"
	"github.com/ArtixSx/razvilka/internal/publicfetch"
)

// DNSAddressResult proves only a bounded HTTPS observation at the named IP.
// Its actor is this process on the router; it is not evidence for a LAN client
// or for the intended VPN until the scoped executor checks that actual path.
type DNSAddressResult struct {
	Address            string `json:"address"`
	ApplicationPath    string `json:"application_path"`
	Status             string `json:"status"`
	ErrorCode          string `json:"error_code,omitempty"`
	TLSVerified        bool   `json:"tls_verified"`
	ServiceVerified    bool   `json:"service_verified"`
	RouteVerified      bool   `json:"route_verified"`
	HTTPStatus         int    `json:"http_status,omitempty"`
	TCPMS              int64  `json:"tcp_ms"`
	TLSMS              int64  `json:"tls_ms"`
	TTFBMS             int64  `json:"ttfb_ms"`
	ReadMS             int64  `json:"read_ms"`
	BytesRead          int64  `json:"bytes_read"`
	TotalMS            int64  `json:"total_ms"`
	CheckedAt          string `json:"checked_at"`
	ContentFingerprint string `json:"content_fingerprint,omitempty"`
}

func ProbeDNSAddress(ctx context.Context, service catalog.Service, address netip.Addr) DNSAddressResult {
	dialer := &net.Dialer{Timeout: 4 * time.Second, KeepAlive: -1}
	return probeDNSAddress(ctx, service, address, dialer.DialContext, nil)
}

func probeDNSAddress(parent context.Context, service catalog.Service, address netip.Addr, dial func(context.Context, string, string) (net.Conn, error), roots *x509.CertPool) (result DNSAddressResult) {
	result = DNSAddressResult{Address: address.String(), ApplicationPath: "system-routing-unverified", Status: "not-checked", TCPMS: -1, TLSMS: -1, TTFBMS: -1}
	start := time.Now()
	defer func() {
		result.TotalMS = time.Since(start).Milliseconds()
		result.CheckedAt = time.Now().UTC().Format(time.RFC3339Nano)
	}()
	if parent == nil || dial == nil || !publicfetch.PublicAddress(address) || address.Is4In6() || address.Zone() != "" || publicfetch.ValidateURL(service.ProbeURL) != nil {
		result.ErrorCode = "DNS_ADDRESS_PROBE_INVALID"
		return
	}
	origin, _ := url.Parse(service.ProbeURL)
	if _, err := netip.ParseAddr(origin.Hostname()); err == nil {
		result.ErrorCode = "DNS_ADDRESS_NAME_REQUIRED"
		return
	}
	ctx, cancel := context.WithTimeout(parent, 8*time.Second)
	defer cancel()
	var mu sync.Mutex
	var connectAt, tlsAt time.Time
	var tcpMS, tlsMS, ttfbMS int64 = -1, -1, -1
	verified := false
	trace := &httptrace.ClientTrace{
		ConnectStart: func(_, _ string) { mu.Lock(); connectAt = time.Now(); mu.Unlock() },
		ConnectDone: func(_, _ string, err error) {
			mu.Lock()
			defer mu.Unlock()
			if err == nil && !connectAt.IsZero() {
				tcpMS = time.Since(connectAt).Milliseconds()
			}
		},
		TLSHandshakeStart: func() { mu.Lock(); tlsAt = time.Now(); mu.Unlock() },
		TLSHandshakeDone: func(state tls.ConnectionState, err error) {
			mu.Lock()
			defer mu.Unlock()
			if err == nil && !tlsAt.IsZero() {
				tlsMS = time.Since(tlsAt).Milliseconds()
				verified = len(state.VerifiedChains) > 0
			}
		},
		GotFirstResponseByte: func() {
			mu.Lock()
			if ttfbMS < 0 {
				ttfbMS = time.Since(start).Milliseconds()
			}
			mu.Unlock()
		},
	}
	defer func() {
		mu.Lock()
		result.TCPMS, result.TLSMS, result.TTFBMS, result.TLSVerified = tcpMS, tlsMS, ttfbMS, verified
		mu.Unlock()
	}()
	// New transport for every address, no environment proxy, pooling, fallback
	// resolver, cross-origin redirect, or TLS verification override.
	transport := &http.Transport{Proxy: nil, DisableKeepAlives: true, DisableCompression: true, ForceAttemptHTTP2: true,
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, ServerName: origin.Hostname(), RootCAs: roots}, TLSHandshakeTimeout: 4 * time.Second, ResponseHeaderTimeout: 5 * time.Second, MaxResponseHeaderBytes: 32 * 1024,
		DialContext: func(ctx context.Context, network, target string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(target)
			if err != nil || !strings.EqualFold(strings.TrimSuffix(host, "."), strings.TrimSuffix(origin.Hostname(), ".")) || port != "443" || network != "tcp" && network != "tcp4" && network != "tcp6" {
				return nil, errors.New("pinned DNS probe target changed")
			}
			family := "tcp4"
			if address.Is6() {
				family = "tcp6"
			}
			return dial(ctx, family, net.JoinHostPort(address.String(), "443"))
		},
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	request, err := http.NewRequestWithContext(httptrace.WithClientTrace(ctx, trace), http.MethodGet, service.ProbeURL, nil)
	if err != nil {
		result.ErrorCode = "DNS_ADDRESS_PROBE_INVALID"
		return
	}
	request.Header.Set("User-Agent", "RAZVILKA-DNS-Probe/1")
	request.Header.Set("Accept", "text/html,application/json;q=0.9,*/*;q=0.1")
	request.Header.Set("Range", "bytes=0-32767")
	result.Status = "fail"
	response, err := client.Do(request)
	if err != nil {
		result.ErrorCode = "DNS_ADDRESS_CONNECT_FAILED"
		var certificateError *tls.CertificateVerificationError
		if errors.As(err, &certificateError) {
			result.ErrorCode = "DNS_ADDRESS_TLS_FAILED"
		}
		if errors.Is(err, context.Canceled) {
			result.ErrorCode = "DNS_ADDRESS_CANCELED"
		} else if errors.Is(err, context.DeadlineExceeded) {
			result.ErrorCode = "DNS_ADDRESS_TIMEOUT"
		}
		return
	}
	defer response.Body.Close()
	readAt := time.Now()
	body, readErr := io.ReadAll(io.LimitReader(response.Body, probecheck.MaxBodyBytes))
	result.ReadMS = time.Since(readAt).Milliseconds()
	result.BytesRead = int64(len(body))
	result.HTTPStatus = response.StatusCode
	if readErr != nil {
		result.ErrorCode = "DNS_ADDRESS_BODY_FAILED"
		return
	}
	observation := probecheck.Observation{RequestedURL: service.ProbeURL, FinalURL: probecheck.FinalURL(response, service.ProbeURL), HTTPStatus: response.StatusCode, ContentType: response.Header.Get("Content-Type"), Body: body, BodyTruncated: len(body) >= probecheck.MaxBodyBytes || response.ContentLength > int64(len(body))}
	verdict := probecheck.Evaluate(service, probecheck.ServiceProbe(service), observation)
	if ctx.Err() != nil {
		result.ErrorCode = "DNS_ADDRESS_CANCELED"
		return
	}
	result.Status, result.ErrorCode, result.ContentFingerprint = verdict.Status, verdict.ErrorCode, verdict.ContentFingerprint
	mu.Lock()
	result.ServiceVerified = verified && verdict.Status == "pass"
	mu.Unlock()
	return
}
