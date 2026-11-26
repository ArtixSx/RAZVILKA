package dnscontrol

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"time"
)

// Only these built-in endpoints have reviewed, provider-published bootstrap
// addresses. A custom URL (even with the same provider ID) cannot inherit them.
// https://developers.cloudflare.com/1.1.1.1/infrastructure/network-operators/
// https://docs.quad9.net/services/ (checked 2026-09-23)
func dohBootstrapIPs(provider, endpoint string) []string {
	switch {
	case provider == "cloudflare" && endpoint == "https://cloudflare-dns.com/dns-query":
		return []string{"1.1.1.1", "2606:4700:4700::1111"}
	case provider == "quad9" && endpoint == "https://dns.quad9.net/dns-query":
		return []string{"9.9.9.9", "2620:fe::fe"}
	case provider == "quad9-unfiltered" && endpoint == "https://dns10.quad9.net/dns-query":
		return []string{"9.9.9.10", "2620:fe::10"}
	}
	return nil
}

func dohTransport(endpoint *url.URL, pins []string, trustedLocal bool) (*http.Transport, error) {
	if len(pins) > 2 {
		return nil, errors.New("too many DoH bootstrap addresses")
	}
	addresses := make([]netip.Addr, 0, len(pins))
	for _, value := range pins {
		ip, err := netip.ParseAddr(value)
		if err != nil || ip.Is4In6() || ip.Zone() != "" || !publicDNSAddress(ip) {
			return nil, errors.New("invalid public DoH bootstrap address")
		}
		addresses = append(addresses, ip)
	}
	return &http.Transport{
		Proxy: nil, DisableKeepAlives: true, ForceAttemptHTTP2: true,
		TLSClientConfig:     dnsTLSConfig(endpoint.Hostname()),
		TLSHandshakeTimeout: 3 * time.Second, ResponseHeaderTimeout: 4 * time.Second,
		MaxResponseHeaderBytes: 32 << 10,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			if len(addresses) == 0 {
				return dialDNSContext(ctx, network, address, trustedLocal)
			}
			return dialDoHBootstrap(ctx, network, address, normalizedHTTPSOrigin(endpoint), addresses, (&net.Dialer{}).DialContext)
		},
	}, nil
}

// The original URL remains responsible for SNI/Host and certificate validation.
// This changes only the TCP destination; no plaintext DNS query or fallback is
// made for an endpoint with reviewed bootstrap addresses.
func dialDoHBootstrap(ctx context.Context, network, address, expected string, ips []netip.Addr, dial func(context.Context, string, string) (net.Conn, error)) (net.Conn, error) {
	if address != expected || len(ips) == 0 || len(ips) > 2 {
		return nil, errors.New("DoH bootstrap origin mismatch")
	}
	_, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	var last error
	for _, ip := range ips {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		attempt, cancel := context.WithTimeout(ctx, 2*time.Second)
		connection, err := dial(attempt, network, net.JoinHostPort(ip.String(), port))
		cancel()
		if err == nil {
			return connection, nil
		}
		last = err
	}
	return nil, last
}

type dohStatusError int

func (e dohStatusError) Error() string { return fmt.Sprintf("DoH endpoint returned HTTP %d", int(e)) }

// Fixed categories only: never publish arbitrary transport errors, account
// paths or endpoint query strings in a diagnostic DTO.
func serviceDNSErrorCode(err error) string {
	var dns *net.DNSError
	var certificate *tls.CertificateVerificationError
	var authority x509.UnknownAuthorityError
	var hostname x509.HostnameError
	var status dohStatusError
	var network net.Error
	switch {
	case errors.Is(err, errDNSAnswer):
		return "DNS_INTEGRITY_FAILED"
	case errors.As(err, &dns):
		return "DNS_BOOTSTRAP_FAILED"
	case errors.As(err, &certificate), errors.As(err, &authority), errors.As(err, &hostname):
		return "DNS_TLS_FAILED"
	case errors.As(err, &status):
		return "DNS_HTTP_REJECTED"
	case errors.Is(err, context.DeadlineExceeded), errors.As(err, &network) && network.Timeout():
		return "DNS_QUERY_TIMEOUT"
	default:
		return "DNS_QUERY_FAILED"
	}
}
