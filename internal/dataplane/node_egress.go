package dataplane

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
	"strconv"
	"strings"
	"time"

	"github.com/ArtixSx/razvilka/internal/publicfetch"
	xnetproxy "golang.org/x/net/proxy"
)

type nodeEgressEndpoint struct {
	url    string
	trace  bool
	pinned netip.Addr
}

type nodeEgressGetter func(context.Context, nodeEgressEndpoint, string) (string, error)

type nodeEgressPair struct {
	directIP, proxyIP   string
	directErr, proxyErr error
}

// The pair must use the same HTTPS provider and literal destination. Otherwise
// destination-based WAN selection could produce two direct public IPs and be
// mistaken for a verified proxy exit. Retry the whole pair, never half of it.
func probeNodeEgressPair(ctx context.Context, proxyAddress string, get nodeEgressGetter) nodeEgressPair {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	production := get == nil
	httpProbe := nodeEgressHTTP{}
	if get == nil {
		get = httpProbe.get
	}
	var result nodeEgressPair
	for _, endpoint := range []nodeEgressEndpoint{{url: "https://www.cloudflare.com/cdn-cgi/trace", trace: true}, {url: "https://api.ipify.org/"}} {
		if err := ctx.Err(); err != nil {
			return nodeEgressPair{directErr: err, proxyErr: err}
		}
		provider, done := context.WithTimeout(ctx, 10*time.Second)
		if production {
			resolveCtx, stop := context.WithTimeout(provider, 5*time.Second)
			pinned, err := httpProbe.pin(resolveCtx, endpoint)
			stop()
			if err != nil {
				done()
				result = nodeEgressPair{directErr: err, proxyErr: err}
				continue
			}
			endpoint = pinned
		}
		measure := func(address string) (string, error) {
			attempt, stop := context.WithTimeout(provider, 5*time.Second)
			defer stop()
			if err := attempt.Err(); err != nil {
				return "", err
			}
			ip, err := get(attempt, endpoint, address)
			if attempt.Err() != nil {
				return "", attempt.Err()
			}
			parsed, parseErr := netip.ParseAddr(strings.TrimSpace(ip))
			if err != nil || parseErr != nil || !parsed.Is4() || parsed.Is4In6() || !publicfetch.PublicAddress(parsed) {
				return "", errors.New("public IPv4 egress measurement is unavailable")
			}
			return parsed.String(), nil
		}
		result.directIP, result.directErr = measure("")
		result.proxyIP, result.proxyErr = measure(proxyAddress)
		done()
		if err := ctx.Err(); err != nil {
			return nodeEgressPair{directErr: err, proxyErr: err}
		}
		if result.directErr == nil && result.proxyErr == nil {
			return result
		}
	}
	return result
}

// Both direct control and the isolated node use the same fixed HTTPS sources
// and IPv4 family. Losing one measurement service must not silently waive the
// direct negative control. This is an IP observation, not geolocation or WARP
// registration evidence.
func probeNodeEgress(ctx context.Context, proxyAddress string, get nodeEgressGetter) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if get == nil {
		get = (nodeEgressHTTP{}).get
	}
	for _, endpoint := range []nodeEgressEndpoint{{url: "https://www.cloudflare.com/cdn-cgi/trace", trace: true}, {url: "https://api.ipify.org/"}} {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		attempt, stop := context.WithTimeout(ctx, 5*time.Second)
		ip, err := get(attempt, endpoint, proxyAddress)
		attemptErr := attempt.Err()
		stop()
		if err := ctx.Err(); err != nil {
			return "", err
		}
		parsed, parseErr := netip.ParseAddr(strings.TrimSpace(ip))
		if err == nil && attemptErr == nil && parseErr == nil && parsed.Is4() && !parsed.Is4In6() && publicfetch.PublicAddress(parsed) {
			return parsed.String(), nil
		}
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	return "", errors.New("public IPv4 egress measurement is unavailable")
}

// Fields inject local resolver/socket/CA fixtures only. Production always uses
// the zero value, OS certificate roots and a real direct or loopback SOCKS dial.
type nodeEgressHTTP struct {
	resolve func(context.Context, string, string) ([]netip.Addr, error)
	dial    func(context.Context, string, string) (net.Conn, error)
	roots   *x509.CertPool
}

func (p nodeEgressHTTP) get(ctx context.Context, endpoint nodeEgressEndpoint, proxyAddress string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if publicfetch.ValidateURL(endpoint.url) != nil {
		return "", errors.New("egress endpoint must be public HTTPS")
	}
	origin, _ := url.Parse(endpoint.url)
	if !endpoint.pinned.IsValid() {
		var err error
		endpoint, err = p.pin(ctx, endpoint)
		if err != nil {
			return "", err
		}
	}
	pinned := endpoint.pinned
	if !pinned.Is4() || pinned.Is4In6() || !publicfetch.PublicAddress(pinned) {
		return "", errors.New("egress pin is not public IPv4")
	}
	dial := p.dial
	if dial == nil {
		dial = (&net.Dialer{Timeout: 3 * time.Second}).DialContext
	}
	if proxyAddress != "" {
		host, port, err := net.SplitHostPort(proxyAddress)
		ip, ipErr := netip.ParseAddr(host)
		number, portErr := strconv.Atoi(port)
		if err != nil || ipErr != nil || !ip.IsLoopback() || ip.Zone() != "" || portErr != nil || number < 1 || number > 65535 {
			return "", errors.New("egress proxy must be a literal loopback listener")
		}
		socks, err := xnetproxy.SOCKS5("tcp", proxyAddress, nil, &net.Dialer{Timeout: 3 * time.Second})
		if err != nil {
			return "", errors.New("egress SOCKS transport is unavailable")
		}
		contextDialer, ok := socks.(xnetproxy.ContextDialer)
		if !ok {
			return "", errors.New("egress SOCKS transport cannot honor cancellation")
		}
		dial = contextDialer.DialContext
	}
	transport := &http.Transport{
		Proxy: nil, DisableKeepAlives: true, DisableCompression: true,
		TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: p.roots, ServerName: origin.Hostname()},
		TLSHandshakeTimeout: 3 * time.Second, ResponseHeaderTimeout: 3 * time.Second, MaxResponseHeaderBytes: 16 << 10,
		DialContext: func(ctx context.Context, network, target string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(target)
			if err != nil || !samePinnedServiceHost(host, origin.Hostname()) || port != "443" || network != "tcp" && network != "tcp4" {
				return nil, errors.New("egress transport target changed")
			}
			return dial(ctx, "tcp4", net.JoinHostPort(pinned.String(), "443"))
		},
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.url, nil)
	if err != nil {
		return "", errors.New("egress request is invalid")
	}
	request.Header.Set("User-Agent", "RAZVILKA-Node-Check/1")
	response, err := client.Do(request)
	if err != nil {
		return "", errors.New("egress HTTPS request failed")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return "", errors.New("egress HTTPS status is not successful")
	}
	limit := int64(128)
	if endpoint.trace {
		limit = 16 << 10
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, limit+1))
	defer clear(body)
	if err != nil || int64(len(body)) > limit {
		return "", errors.New("egress response exceeds its bound")
	}
	value := strings.TrimSpace(string(body))
	if endpoint.trace {
		trace, err := parseCloudflareTrace(value)
		if err != nil {
			return "", errors.New("egress trace is invalid")
		}
		value = trace.EgressIP
	}
	address, err := netip.ParseAddr(value)
	if err != nil || !address.Is4() || address.Is4In6() || !publicfetch.PublicAddress(address) {
		return "", errors.New("egress response is not public IPv4")
	}
	return address.String(), nil
}

func (p nodeEgressHTTP) pin(ctx context.Context, endpoint nodeEgressEndpoint) (nodeEgressEndpoint, error) {
	if publicfetch.ValidateURL(endpoint.url) != nil {
		return endpoint, errors.New("egress endpoint must be public HTTPS")
	}
	origin, _ := url.Parse(endpoint.url)
	resolve := p.resolve
	if resolve == nil {
		resolve = net.DefaultResolver.LookupNetIP
	}
	addresses, err := resolve(ctx, "ip", origin.Hostname())
	if err != nil || len(addresses) == 0 || len(addresses) > 16 {
		return endpoint, errors.New("egress endpoint DNS is unavailable")
	}
	for _, address := range addresses {
		if address.Is4In6() || !publicfetch.PublicAddress(address) {
			return endpoint, errors.New("egress endpoint DNS is not public")
		}
		if !endpoint.pinned.IsValid() && address.Is4() {
			endpoint.pinned = address
		}
	}
	if !endpoint.pinned.IsValid() {
		return endpoint, errors.New("egress endpoint has no public IPv4")
	}
	return endpoint, nil
}
