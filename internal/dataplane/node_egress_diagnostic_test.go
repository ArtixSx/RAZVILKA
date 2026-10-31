package dataplane

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestNodeEgressDiagnosticCategoriesFromLocalHTTPSAndSOCKS(t *testing.T) {
	// A stalled response used to collapse to the bare "timeout"; it now names
	// the stage the request had reached.
	for _, category := range []string{"certificate", "tls_handshake", "socks_connect", "http_status", "body_parse", "response_timeout"} {
		t.Run(category, func(t *testing.T) {
			server, roots, _ := newPinnedTLSFixture(t, func(w http.ResponseWriter, r *http.Request) {
				if category == "response_timeout" {
					<-r.Context().Done()
					return
				}
				if category == "http_status" {
					w.WriteHeader(http.StatusForbidden)
					return
				}
				_, _ = io.WriteString(w, "private-profile-marker-not-an-IP")
			})
			probe := nodeEgressHTTP{roots: roots.RootCAs, dial: func(ctx context.Context, network, target string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "tcp", server.Listener.Addr().String())
			}}
			address := ""
			switch category {
			case "certificate":
				probe.roots = nil
			case "socks_connect":
				address = newPinnedSOCKSFixture(t, server.Listener.Addr().String(), true).address
			case "tls_handshake":
				probe.dial = func(context.Context, string, string) (net.Conn, error) {
					client, peer := net.Pipe()
					go func() {
						defer peer.Close()
						buffer := make([]byte, 4096)
						_, _ = peer.Read(buffer)
						_, _ = io.WriteString(peer, "HTTP/1.1 400 private-profile-marker\r\n\r\n")
					}()
					return client, nil
				}
			}
			ctx := context.Background()
			if category == "response_timeout" {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, 500*time.Millisecond)
				defer cancel()
			}
			ip, err := probe.get(ctx, nodeEgressEndpoint{url: "https://example.com/", pinned: netip.MustParseAddr("1.1.1.1")}, address)
			if ip != "" || nodeEgressErrorCategory(err) != category || strings.Contains(fmt.Sprint(err), "private-profile-marker") {
				t.Fatalf("category=%s ip=%q safe-error=%v", category, ip, err)
			}
		})
	}
}

func TestNodeEgressDiagnosticSurvivesPairAndResultWithoutChangingFailure(t *testing.T) {
	for _, category := range []string{"socks_connect", "tls_handshake", "certificate", "http_status", "timeout", "body_parse", "dial_timeout", "tls_timeout", "response_timeout"} {
		var calls atomic.Int32
		pair := probeNodeEgressPair(context.Background(), "127.0.0.1:1080", func(_ context.Context, _ nodeEgressEndpoint, address string) (string, error) {
			calls.Add(1)
			if address == "" {
				return "8.8.8.8", nil
			}
			return "", nodeEgressFailure(category)
		})
		if calls.Load() != 4 || nodeEgressErrorCategory(pair.proxyErr) != category {
			t.Fatalf("category=%s provider retry changed: calls=%d error=%v", category, calls.Load(), pair.proxyErr)
		}
		checker := fakeExactNodeChecker(t)
		checker.egressPair = func(context.Context, string) nodeEgressPair { return pair }
		result, err := checker.Check(context.Background(), checkedNodeRequest())
		if err != nil || result.Available || result.ErrorCode != "node-egress-failed" || result.TestLevel != "protocol" || result.DirectControl != "measured" || result.ProxyEgressError != category || result.DirectEgressError != "" {
			t.Fatalf("category=%s result=%+v err=%v", category, result, err)
		}
	}
	checker := fakeExactNodeChecker(t)
	checker.proxyEgress = func(context.Context, string) (string, error) {
		return "", errors.New("private-profile-marker https://credential@example.invalid")
	}
	result, _ := checker.Check(context.Background(), checkedNodeRequest())
	data, _ := json.Marshal(result)
	if result.ProxyEgressError != "unavailable" || strings.Contains(string(data), "private-profile-marker") || strings.Contains(string(data), "credential") {
		t.Fatal("unrecognized error escaped closed diagnostic boundary")
	}
	if nodeEgressErrorCategory(nodeEgressFailure("private-profile-marker")) != "unavailable" {
		t.Fatal("unrecognized diagnostic value accepted")
	}
}
