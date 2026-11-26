package community

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/url"

	"github.com/ArtixSx/razvilka/internal/publicfetch"
)

// Official Telegram networks reviewed on 2026-10-20, from this exact URL.
// This bundled snapshot is deliberately not an ASN/third-party aggregation.
const telegramCIDRsURL = "https://core.telegram.org/resources/cidr.txt"
const telegramSnapshotDate = "2026-10-20"
const telegramSnapshot = `91.108.56.0/22
91.108.4.0/22
91.108.8.0/22
91.108.16.0/22
91.108.12.0/22
149.154.160.0/20
91.105.192.0/23
91.108.20.0/22
185.76.151.0/24
2001:b28:f23d::/48
2001:b28:f23f::/48
2001:67c:4e8::/48
2001:b28:f23c::/48
2a0a:f280::/32
`

type sourceNetworkFailure struct{ err error }

func (e *sourceNetworkFailure) Error() string { return e.err.Error() }
func (e *sourceNetworkFailure) Unwrap() error { return e.err }

// Only direct network unavailability qualifies. Never hide policy, redirect,
// certificate, caller cancellation, HTTP, body-read or parsing failures.
func directNetworkFailure(ctx context.Context, rawURL string, err error) bool {
	if ctx.Err() != nil || errors.Is(err, context.Canceled) {
		return false
	}
	for _, forbidden := range []error{publicfetch.ErrURL, publicfetch.ErrAddress, publicfetch.ErrRedirect, publicfetch.ErrRedirectLimit} {
		if errors.Is(err, forbidden) {
			return false
		}
	}
	var cert *tls.CertificateVerificationError
	if errors.As(err, &cert) {
		return false
	}
	var request *url.Error
	if !errors.As(err, &request) || request.URL != rawURL {
		return false
	}
	var dns *net.DNSError
	if errors.As(err, &dns) {
		return true
	}
	var op *net.OpError
	if errors.As(err, &op) && op.Op == "dial" {
		return true
	}
	return false
}

func telegramFallbackAllowed(entry Entry, err error) bool {
	var unavailable *sourceNetworkFailure
	return entry.ID == "telegram-ip" && entry.CIDRsURL == telegramCIDRsURL &&
		entry.SourcePage == telegramCIDRsURL && entry.DomainsURL == "" && entry.ListURL == "" &&
		errors.As(err, &unavailable)
}
