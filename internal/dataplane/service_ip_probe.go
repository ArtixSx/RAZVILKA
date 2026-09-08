package dataplane

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ArtixSx/razvilka/internal/publicfetch"
	xnetproxy "golang.org/x/net/proxy"
)

// socksHTTPGetPinned tests the IP destination a routed LAN client actually
// uses. The caller must resolve/admit this public IPv4 against the service's
// route scope first. This transport never resolves the service hostname or
// retries a hostname/direct connection. Body bounds and semantic acceptance
// remain with the caller's existing probecheck evaluation.
func socksHTTPGetPinned(ctx context.Context, rawURL, address string, pinned netip.Addr) (*http.Response, func(), error) {
	return socksHTTPGetPinnedTLS(ctx, rawURL, address, pinned, nil)
}

// A test CA may be supplied here; production uses system roots. ServerName is
// always derived from the original URL and verification cannot be disabled.
func socksHTTPGetPinnedTLS(ctx context.Context, rawURL, address string, pinned netip.Addr, roots *tls.Config) (*http.Response, func(), error) {
	if ctx == nil {
		return nil, nil, errors.New("pinned service context is required")
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	if publicfetch.ValidateURL(rawURL) != nil {
		return nil, nil, errors.New("pinned service requires public HTTPS on port 443")
	}
	origin, _ := url.Parse(rawURL)
	if !pinned.Is4() || pinned.Is4In6() || !publicfetch.PublicAddress(pinned) {
		return nil, nil, errors.New("pinned service destination must be public IPv4")
	}
	if literal, err := netip.ParseAddr(origin.Hostname()); err == nil && literal != pinned {
		return nil, nil, errors.New("pinned service destination differs from its literal URL")
	}
	proxyHost, proxyPort, err := net.SplitHostPort(address)
	proxyIP, ipErr := netip.ParseAddr(proxyHost)
	port, portErr := strconv.Atoi(proxyPort)
	if err != nil || ipErr != nil || !proxyIP.IsLoopback() || proxyIP.Zone() != "" || portErr != nil || port < 1 || port > 65535 {
		return nil, nil, errors.New("pinned service requires a literal loopback SOCKS endpoint")
	}
	if roots != nil && roots.InsecureSkipVerify {
		return nil, nil, errors.New("pinned service TLS verification cannot be disabled")
	}
	config := &tls.Config{MinVersion: tls.VersionTLS12}
	if roots != nil {
		config = roots.Clone()
		if config.MinVersion < tls.VersionTLS12 {
			config.MinVersion = tls.VersionTLS12
		}
	}
	config.ServerName = origin.Hostname()
	dialer, err := xnetproxy.SOCKS5("tcp", address, nil, &net.Dialer{Timeout: 5 * time.Second})
	if err != nil {
		return nil, nil, errors.New("pinned service SOCKS transport is unavailable")
	}
	contextDialer, ok := dialer.(xnetproxy.ContextDialer)
	if !ok {
		return nil, nil, errors.New("pinned service SOCKS transport cannot honor cancellation")
	}
	requestCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	transport := &http.Transport{
		TLSClientConfig: config, TLSHandshakeTimeout: 5 * time.Second,
		ResponseHeaderTimeout: 10 * time.Second, ForceAttemptHTTP2: true,
		DialContext: func(ctx context.Context, network, target string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(target)
			if err != nil || !samePinnedServiceHost(host, origin.Hostname()) || port != "443" || network != "tcp" && network != "tcp4" {
				return nil, errors.New("pinned service transport target changed")
			}
			return contextDialer.DialContext(ctx, "tcp", net.JoinHostPort(pinned.String(), "443"))
		},
	}
	var once sync.Once
	cleanup := func() { once.Do(func() { cancel(); transport.CloseIdleConnections() }) }
	request, err := http.NewRequestWithContext(requestCtx, http.MethodGet, rawURL, nil)
	if err != nil {
		cleanup()
		return nil, nil, errors.New("pinned service request is invalid")
	}
	request.Header.Set("User-Agent", "RAZVILKA-Proxy-Health/1")
	client := serviceProbeClient(&http.Client{Transport: transport, Timeout: 15 * time.Second}, rawURL)
	previous := client.CheckRedirect
	client.CheckRedirect = func(request *http.Request, via []*http.Request) error {
		if request.URL.Scheme != "https" || request.URL.User != nil || !samePinnedServiceHost(request.URL.Hostname(), origin.Hostname()) || request.URL.Port() != "" && request.URL.Port() != "443" {
			return errors.New("pinned service redirect changed its origin")
		}
		return previous(request, via)
	}
	response, err := client.Do(request)
	if err != nil {
		cleanup()
		// Preserve cancellation and TLS errors without including query values.
		var requestErr *url.Error
		if errors.As(err, &requestErr) {
			err = requestErr.Err
		}
		return nil, nil, fmt.Errorf("pinned service request failed: %w", err)
	}
	return response, cleanup, nil
}

func samePinnedServiceHost(a, b string) bool {
	return strings.EqualFold(strings.TrimSuffix(a, "."), strings.TrimSuffix(b, "."))
}
