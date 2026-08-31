// Package publicfetch is the network boundary for remote list/catalog data.
// It never uses environment proxies, private DNS answers or TLS bypasses.
package publicfetch

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"
)

var (
	ErrURL           = errors.New("source requires public HTTPS on port 443 without credentials or fragment")
	ErrAddress       = errors.New("source DNS contains a non-public address")
	ErrRedirect      = errors.New("source redirect origin is not explicitly allowed")
	ErrRedirectLimit = errors.New("too many source redirects")
)

var excluded = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"), netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"), netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"), netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"), netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("64:ff9b::/96"), netip.MustParsePrefix("64:ff9b:1::/48"),
	netip.MustParsePrefix("2001::/32"), netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("2002::/16"),
}

func PublicAddress(ip netip.Addr) bool {
	if ip.Zone() != "" {
		return false
	}
	ip = ip.Unmap()
	if !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		return false
	}
	for _, prefix := range excluded {
		if prefix.Contains(ip) {
			return false
		}
	}
	return true
}

func ValidateURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Fragment != "" || u.Opaque != "" || u.Port() != "" && u.Port() != "443" {
		return ErrURL
	}
	if !validHost(u.Hostname()) {
		return ErrURL
	}
	return nil
}

func validHost(host string) bool {
	if ip, err := netip.ParseAddr(host); err == nil {
		return PublicAddress(ip)
	}
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if len(host) > 253 || !strings.Contains(host, ".") {
		return false
	}
	for _, suffix := range []string{".localhost", ".local", ".lan", ".home.arpa"} {
		if strings.HasSuffix(host, suffix) {
			return false
		}
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}

func NewClient(timeout time.Duration) *http.Client {
	if timeout <= 0 || timeout > 25*time.Second {
		timeout = 25 * time.Second
	}
	return &http.Client{Timeout: timeout, Transport: checkedTransport{next: transport()}, CheckRedirect: func(*http.Request, []*http.Request) error { return ErrRedirect }}
}

func transport() *http.Transport {
	return &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			dialer := &net.Dialer{Timeout: 6 * time.Second, KeepAlive: 30 * time.Second}
			return resolveAndDial(ctx, network, address, net.DefaultResolver.LookupNetIP, dialer.DialContext)
		},
		TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout: 6 * time.Second, ResponseHeaderTimeout: 10 * time.Second,
		IdleConnTimeout: 30 * time.Second, MaxIdleConns: 8, MaxIdleConnsPerHost: 2,
		MaxConnsPerHost: 2, MaxResponseHeaderBytes: 64 << 10,
		ForceAttemptHTTP2: true,
	}
}

type lookupFunc func(context.Context, string, string) ([]netip.Addr, error)
type dialFunc func(context.Context, string, string) (net.Conn, error)

func resolveAndDial(ctx context.Context, network, address string, lookup lookupFunc, dial dialFunc) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	host, port, err := net.SplitHostPort(address)
	if err != nil || port != "443" || !validHost(host) {
		return nil, ErrURL
	}
	var addresses []netip.Addr
	if ip, err := netip.ParseAddr(host); err == nil {
		addresses = []netip.Addr{ip}
	} else {
		addresses, err = lookup(ctx, "ip", host)
		if err != nil {
			return nil, err
		}
	}
	if len(addresses) == 0 || len(addresses) > 32 {
		return nil, ErrAddress
	}
	// Reject mixed public/private answers rather than trying the private one
	// after a failed public connection. Dial only the checked literal IPs;
	// never resolve the name again between validation and connection.
	for _, ip := range addresses {
		if !PublicAddress(ip) {
			return nil, ErrAddress
		}
	}
	for _, ip := range addresses {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		var conn net.Conn
		conn, err = dial(ctx, network, net.JoinHostPort(ip.Unmap().String(), port))
		if err == nil {
			return conn, nil
		}
	}
	return nil, err
}

// WithPolicy copies a trusted in-process client. Custom transports are intended
// for dependency injection/tests, never for URL-controlled proxy/TLS settings.
// A nil/default transport is replaced by the public-only transport above.
func WithPolicy(base *http.Client, origin string, redirectHosts []string) *http.Client {
	if base == nil {
		base = NewClient(25 * time.Second)
	}
	client := *base
	if client.Transport == nil || client.Transport == http.DefaultTransport {
		client.Transport = transport()
	}
	client.Transport = checkedTransport{next: client.Transport}
	client.Jar = nil
	if client.Timeout <= 0 || client.Timeout > 25*time.Second {
		client.Timeout = 25 * time.Second
	}
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) >= 5 {
			return ErrRedirectLimit
		}
		if req.URL == nil || ValidateURL(req.URL.String()) != nil {
			return ErrURL
		}
		original, err := url.Parse(origin)
		if err != nil || ValidateURL(origin) != nil {
			return ErrURL
		}
		host := strings.ToLower(req.URL.Hostname())
		allowed := strings.EqualFold(host, original.Hostname())
		for _, target := range redirectHosts {
			allowed = allowed || strings.EqualFold(host, target)
		}
		if !allowed {
			return ErrRedirect
		}
		for _, name := range []string{"Authorization", "Proxy-Authorization", "Cookie", "Referer"} {
			req.Header.Del(name)
		}
		return nil
	}
	return &client
}

type checkedTransport struct{ next http.RoundTripper }

func (t checkedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL == nil || ValidateURL(req.URL.String()) != nil {
		return nil, ErrURL
	}
	return t.next.RoundTrip(req)
}

// RedactedURL omits paths as well as credentials/query: subscription tokens may
// be embedded anywhere in a URL, not just in a parameter called "token".
func RedactedURL(raw string) string {
	if ValidateURL(raw) != nil {
		return "[invalid source URL]"
	}
	u, _ := url.Parse(raw)
	return "https://" + u.Host + "/"
}

func SafeError(err error) error {
	for _, safe := range []error{context.Canceled, context.DeadlineExceeded, ErrURL, ErrAddress, ErrRedirect, ErrRedirectLimit} {
		if errors.Is(err, safe) {
			return safe
		}
	}
	var cert *tls.CertificateVerificationError
	if errors.As(err, &cert) {
		return errors.New("source TLS certificate verification failed")
	}
	return errors.New("source network request failed; check DNS, HTTPS and availability")
}
