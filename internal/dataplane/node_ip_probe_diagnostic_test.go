package dataplane

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestNodeIPProbeDiagnosticClosedCategoriesDoNotRetainPrivateErrors(t *testing.T) {
	const private = "https://secret.invalid/?password=private-uuid"
	cert := &x509.Certificate{Subject: pkix.Name{CommonName: private}, DNSNames: []string{private}}
	for _, tc := range []struct {
		name, reason string
		err, ctxErr  error
	}{
		{"deadline", "timeout", fmt.Errorf("%s: %w", private, context.DeadlineExceeded), nil},
		{"probe-deadline", "timeout", errors.New(private), context.DeadlineExceeded},
		{"network-timeout", "timeout", &net.DNSError{Name: private, IsTimeout: true}, nil},
		{"certificate", "tls-certificate", &tls.CertificateVerificationError{UnverifiedCertificates: []*x509.Certificate{cert}, Err: errors.New(private)}, nil},
		{"hostname", "tls-certificate", x509.HostnameError{Certificate: cert, Host: private}, nil},
		{"authority", "tls-certificate", x509.UnknownAuthorityError{Cert: cert}, nil},
		{"protocol", "tls-protocol", tls.RecordHeaderError{Msg: private}, nil},
		{"io-eof", "io", fmt.Errorf("%s: %w", private, io.ErrUnexpectedEOF), nil},
		{"io-operation", "io", &net.OpError{Op: private, Net: private, Err: errors.New(private)}, nil},
		{"unknown", "unknown", errors.New("TLS handshake failed " + private), nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			wrapped := &url.Error{Op: private, URL: private, Err: tc.err}
			got := classifyNodeIPProbeFailure(wrapped, tc.ctxErr)
			if got.Error() != "node service IP path unsupported or unavailable; reason="+tc.reason {
				t.Fatal("wrong closed diagnostic", got)
			}
			encoded, err := json.Marshal(got)
			if err != nil || strings.Contains(fmt.Sprintf("%v %#v %s", got, got, encoded), "secret.invalid") || errors.Unwrap(got) != nil || errors.Is(got, context.DeadlineExceeded) {
				t.Fatal("diagnostic retained private cause or changed cancellation semantics")
			}
			var certificate *tls.CertificateVerificationError
			if errors.As(got, &certificate) {
				t.Fatal("private certificate escaped sanitization")
			}
		})
	}
	if got := (nodeIPProbeFailure{nodeIPProbeReason(255)}).Error(); !strings.HasSuffix(got, "reason=unknown") {
		t.Fatal("unknown enum escaped closed vocabulary")
	}
}

func TestNodeIPProbeDiagnosticKeepsGuardAndSemanticPrecedence(t *testing.T) {
	for _, scenario := range []string{"unknown-before-cancel", "deadline", "parent-canceled", "resource-revoked", "review-revoked", "http-403"} {
		t.Run(scenario, func(t *testing.T) {
			a := &ProxyTunnelAdapter{Timeout: 5 * time.Millisecond}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			revoked := false
			ctx = WithNodeResourceGuard(ctx, func(context.Context, string, netip.Addr) error {
				if revoked && scenario == "resource-revoked" {
					return ErrNodeResourceDenied
				}
				return nil
			})
			ctx = WithReviewGuard(ctx, func(context.Context) error {
				if revoked && scenario == "review-revoked" {
					return ErrReviewChanged
				}
				return nil
			})
			semantic := &serviceResponseError{code: "http-403", detail: "service rejected"}
			calls := 0
			a.ServiceIPProbe = func(probeCtx context.Context, _, _ string, _ netip.Addr) error {
				calls++
				switch scenario {
				case "deadline":
					<-probeCtx.Done()
				case "parent-canceled":
					cancel()
				case "resource-revoked", "review-revoked":
					revoked = true
				case "http-403":
					return semantic
				}
				return errors.New("private-uuid https://secret.invalid/?token=hidden")
			}
			err := a.probeNodeServiceIPPins(ctx, Route{ProbeURL: "https://example.com/"}, "127.0.0.1:1", []netip.Addr{netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("8.8.8.9")})
			if err == nil || calls != 1 {
				t.Fatal("failed probe gained next-pin authority", calls)
			}
			switch scenario {
			case "parent-canceled":
				if !errors.Is(err, context.Canceled) {
					t.Fatal("parent cancellation lost")
				}
			case "resource-revoked":
				if !errors.Is(err, ErrNodeResourceDenied) {
					t.Fatal("resource revocation lost")
				}
			case "review-revoked":
				if !errors.Is(err, ErrReviewChanged) {
					t.Fatal("review revocation lost")
				}
			case "http-403":
				if err != semantic {
					t.Fatal("semantic response attribution changed")
				}
			default:
				want := "unknown"
				if scenario == "deadline" {
					want = "timeout"
				}
				if !strings.HasSuffix(err.Error(), "reason="+want) || strings.Contains(err.Error(), "secret.invalid") {
					t.Fatal("own cleanup cancellation misclassified failure", err)
				}
			}
		})
	}
}

func TestNodeIPProbeDNSDiagnosticRejectsWithoutProbe(t *testing.T) {
	for _, scenario := range []string{"invalid-url", "resolver-error", "private-answer"} {
		t.Run(scenario, func(t *testing.T) {
			a := &ProxyTunnelAdapter{}
			calls := 0
			a.ServiceIPProbe = func(context.Context, string, string, netip.Addr) error { calls++; return nil }
			a.Resolver = func(context.Context, string) ([]netip.Addr, error) {
				if scenario == "resolver-error" {
					return nil, &net.DNSError{Name: "secret.invalid", Err: "private-uuid"}
				}
				return []netip.Addr{netip.MustParseAddr("192.168.1.1")}, nil
			}
			raw := "https://example.com/"
			if scenario == "invalid-url" {
				raw = "https://private-uuid:password@secret.invalid/"
			}
			err := a.probeNodeServiceIP(context.Background(), Route{ProbeURL: raw}, "127.0.0.1:1")
			want := "dns-invalid"
			if scenario == "resolver-error" {
				want = "dns-error"
			}
			if err == nil || !strings.HasSuffix(err.Error(), "reason="+want) || calls != 0 || strings.Contains(err.Error(), "private-uuid") || errors.Unwrap(err) != nil {
				t.Fatal("DNS refusal changed scope or leaked detail", err, calls)
			}
		})
	}
}
