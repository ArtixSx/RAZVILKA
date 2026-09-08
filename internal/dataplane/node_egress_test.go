package dataplane

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/evidence"
)

func TestNodeEgressBackupRetainsMandatoryDirectControlAndLeakRejection(t *testing.T) {
	for _, scenario := range []string{"primary-fails", "all-direct-fail", "all-paths-fail", "backup-direct-leak", "primary-invalid-ip"} {
		t.Run(scenario, func(t *testing.T) {
			checker := fakeExactNodeChecker(t)
			var direct, proxy []string
			get := func(ctx context.Context, endpoint nodeEgressEndpoint, address string) (string, error) {
				deadline, exists := ctx.Deadline()
				if !exists || time.Until(deadline) > 5*time.Second {
					t.Fatal("endpoint has no bounded deadline")
				}
				if address == "" {
					direct = append(direct, endpoint.url)
				} else {
					proxy = append(proxy, endpoint.url)
				}
				if endpoint.trace {
					if scenario == "primary-invalid-ip" {
						return "192.168.1.1", nil
					}
					return "", errors.New("primary unavailable")
				}
				if scenario == "all-paths-fail" {
					return "", errors.New("both providers unavailable")
				}
				if address == "" && scenario == "all-direct-fail" {
					return "", errors.New("backup unavailable")
				}
				if address == "" && scenario != "backup-direct-leak" {
					return "8.8.8.8", nil
				}
				return "1.1.1.1", nil
			}
			checker.egressPair = func(ctx context.Context, address string) nodeEgressPair {
				return probeNodeEgressPair(ctx, address, get)
			}
			result, err := checker.Check(context.Background(), checkedNodeRequest())
			if err != nil {
				t.Fatal(err)
			}
			want := []string{"https://www.cloudflare.com/cdn-cgi/trace", "https://api.ipify.org/"}
			if !reflect.DeepEqual(direct, want) || !reflect.DeepEqual(proxy, want) {
				t.Fatalf("direct/proxy redundancy differs: %v %v", direct, proxy)
			}
			switch scenario {
			case "all-paths-fail":
				if result.Available || result.Verdict != evidence.VerdictInconclusive || result.ErrorCode != "node-egress-control-unavailable" || result.EgressIP != "" {
					t.Fatal("missing control pair claimed node failure or success")
				}
			case "all-direct-fail":
				if result.Available || result.Verdict != evidence.VerdictInconclusive || result.ErrorCode != "node-direct-control-unavailable" || result.EgressIP != "" {
					t.Fatalf("direct control was waived: %+v", result)
				}
			case "backup-direct-leak":
				if result.Available || !result.DirectLeak || result.ErrorCode != "node-direct-leak" || result.EgressIP != "" {
					t.Fatal("backup waived direct leak rejection")
				}
			default:
				if !result.Available || result.DirectControl != "measured" || result.EgressIP != "1.1.1.1" {
					t.Fatalf("backup did not retain exact service gates: %+v", result)
				}
			}
		})
	}
}

func TestNodeEgressPrimarySuccessSkipsBackupAndCancellationCannotPublish(t *testing.T) {
	for _, cancelDuring := range []bool{false, true} {
		ctx, cancel := context.WithCancel(context.Background())
		calls := 0
		ip, err := probeNodeEgress(ctx, "", func(context.Context, nodeEgressEndpoint, string) (string, error) {
			calls++
			if cancelDuring {
				cancel()
			}
			return "8.8.8.8", nil
		})
		cancel()
		if calls != 1 || cancelDuring && (!errors.Is(err, context.Canceled) || ip != "") || !cancelDuring && (err != nil || ip != "8.8.8.8") {
			t.Fatalf("calls=%d result=%q error=%v", calls, ip, err)
		}
	}
}

func TestNodeEgressHTTPSPinsPublicIPv4PreservesTLSAndIgnoresEnvironmentProxy(t *testing.T) {
	for _, viaProxy := range []bool{false, true} {
		t.Run(map[bool]string{true: "socks", false: "direct"}[viaProxy], func(t *testing.T) {
			t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
			t.Setenv("ALL_PROXY", "http://127.0.0.1:1")
			hosts := make(chan string, 1)
			server, roots, names := newPinnedTLSFixture(t, func(w http.ResponseWriter, r *http.Request) {
				hosts <- r.Host
				_, _ = io.WriteString(w, "8.8.8.8\n")
			})
			var lookups, dials int
			p := nodeEgressHTTP{roots: roots.RootCAs, resolve: func(ctx context.Context, network, host string) ([]netip.Addr, error) {
				lookups++
				if host != "example.com" || network != "ip" {
					t.Fatal("resolver origin changed")
				}
				return []netip.Addr{netip.MustParseAddr("1.1.1.1")}, nil
			}, dial: func(ctx context.Context, network, target string) (net.Conn, error) {
				dials++
				if network != "tcp4" || target != "1.1.1.1:443" {
					t.Fatalf("unpinned direct target: %s %s", network, target)
				}
				return (&net.Dialer{}).DialContext(ctx, "tcp", server.Listener.Addr().String())
			}}
			address := ""
			var socks pinnedSOCKSFixture
			if viaProxy {
				socks = newPinnedSOCKSFixture(t, server.Listener.Addr().String(), false)
				address = socks.address
			}
			result, err := p.get(context.Background(), nodeEgressEndpoint{url: "https://example.com/"}, address)
			if err != nil || result != "8.8.8.8" || lookups != 1 || viaProxy && dials != 0 || !viaProxy && dials != 1 {
				t.Fatalf("result=%q err=%v lookups=%d dials=%d", result, err, lookups, dials)
			}
			if host, sni := <-hosts, <-names; host != "example.com" || sni != "example.com" {
				t.Fatalf("origin changed: %s %s", host, sni)
			}
			if viaProxy {
				request := <-socks.requests
				if request.AddressType != 1 || request.Host != "1.1.1.1" || request.Port != 443 {
					t.Fatalf("proxy received hostname/private target: %+v", request)
				}
			}
		})
	}
}

func TestNodeEgressHTTPSRejectsUnsafeDNSResponsesRedirectsAndTLS(t *testing.T) {
	for _, scenario := range []string{"private-dns", "mapped-dns", "mixed-dns", "only-ipv6", "bad-tls", "redirect", "oversize", "private-response", "ipv6-response", "trace", "untrusted-socks"} {
		t.Run(scenario, func(t *testing.T) {
			var requests atomic.Int32
			server, roots, _ := newPinnedTLSFixture(t, func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				switch scenario {
				case "redirect":
					w.Header().Set("Location", "https://127.0.0.1/")
					w.WriteHeader(302)
				case "oversize":
					_, _ = io.WriteString(w, "8.8.8.8"+strings.Repeat(" ", 200))
				case "private-response":
					_, _ = io.WriteString(w, "192.168.1.1")
				case "ipv6-response":
					_, _ = io.WriteString(w, "2606:4700:4700::1111")
				case "trace":
					_, _ = io.WriteString(w, "ip=8.8.8.8\nwarp=off\n")
				default:
					_, _ = io.WriteString(w, "8.8.8.8")
				}
			})
			dials := 0
			p := nodeEgressHTTP{roots: roots.RootCAs, resolve: func(context.Context, string, string) ([]netip.Addr, error) {
				addresses := []netip.Addr{netip.MustParseAddr("1.1.1.1")}
				switch scenario {
				case "private-dns":
					addresses = []netip.Addr{netip.MustParseAddr("192.168.1.1")}
				case "mapped-dns":
					addresses = []netip.Addr{netip.MustParseAddr("::ffff:1.1.1.1")}
				case "mixed-dns":
					addresses = append(addresses, netip.MustParseAddr("127.0.0.1"))
				case "only-ipv6":
					addresses = []netip.Addr{netip.MustParseAddr("2606:4700:4700::1111")}
				}
				return addresses, nil
			}, dial: func(ctx context.Context, network, target string) (net.Conn, error) {
				dials++
				return (&net.Dialer{}).DialContext(ctx, "tcp", server.Listener.Addr().String())
			}}
			if scenario == "bad-tls" {
				p.roots = nil
			}
			address := ""
			if scenario == "untrusted-socks" {
				address = "192.168.1.1:1080"
			}
			result, err := p.get(context.Background(), nodeEgressEndpoint{url: "https://example.com/", trace: scenario == "trace"}, address)
			if (scenario == "trace") != (err == nil) || err != nil && result != "" || requests.Load() > 1 {
				t.Fatalf("scenario=%s result=%q err=%v requests=%d", scenario, result, err, requests.Load())
			}
			if strings.HasSuffix(scenario, "dns") || scenario == "only-ipv6" || scenario == "untrusted-socks" {
				if dials != 0 {
					t.Fatal("unsafe DNS/proxy dialed")
				}
			}
		})
	}
}

func TestNodeEgressCancellationStopsPinnedRequest(t *testing.T) {
	entered := make(chan struct{})
	server, roots, _ := newPinnedTLSFixture(t, func(w http.ResponseWriter, r *http.Request) {
		close(entered)
		<-r.Context().Done()
	})
	p := nodeEgressHTTP{roots: roots.RootCAs, resolve: func(context.Context, string, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("1.1.1.1")}, nil
	}, dial: func(ctx context.Context, network, target string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", server.Listener.Addr().String())
	}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := p.get(ctx, nodeEgressEndpoint{url: "https://example.com/"}, "")
		done <- err
	}()
	<-entered
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("canceled response accepted")
		}
	case <-time.After(time.Second):
		t.Fatal("cancellation did not close pinned connection")
	}
}

func TestNodeEgressPairNeverMixesProviderAddressesOrRetriesAnObservedLeak(t *testing.T) {
	for _, failedPath := range []string{"direct", "proxy", "neither"} {
		t.Run(failedPath, func(t *testing.T) {
			checker := fakeExactNodeChecker(t)
			calls := []string{}
			checker.egressPair = func(ctx context.Context, address string) nodeEgressPair {
				return probeNodeEgressPair(ctx, address, func(ctx context.Context, endpoint nodeEgressEndpoint, proxy string) (string, error) {
					path := "direct"
					if proxy != "" {
						path = "proxy"
					}
					calls = append(calls, endpoint.url+"/"+path)
					if endpoint.trace {
						if failedPath == path {
							return "", errors.New("primary path unavailable")
						}
						return "1.1.1.1", nil
					}
					// The same direct WAN path has a different IP to this provider.
					return "8.8.8.8", nil
				})
			}
			result, err := checker.Check(context.Background(), checkedNodeRequest())
			if err != nil || result.Available || !result.DirectLeak || result.ErrorCode != "node-direct-leak" || result.EgressIP != "" {
				t.Fatalf("mixed-provider direct path accepted: %+v %v", result, err)
			}
			wantCalls := 4
			if failedPath == "neither" {
				wantCalls = 2
			}
			if len(calls) != wantCalls {
				t.Fatalf("observed equal pair was retried: %v", calls)
			}
		})
	}
}

func TestNodeEgressProviderPairSharesOneDNSPinAcrossDirectAndSOCKS(t *testing.T) {
	server, roots, _ := newPinnedTLSFixture(t, func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "8.8.8.8") })
	socks := newPinnedSOCKSFixture(t, server.Listener.Addr().String(), false)
	lookups := 0
	p := nodeEgressHTTP{roots: roots.RootCAs, resolve: func(context.Context, string, string) ([]netip.Addr, error) {
		lookups++
		if lookups == 1 {
			return []netip.Addr{netip.MustParseAddr("1.1.1.1")}, nil
		}
		return []netip.Addr{netip.MustParseAddr("9.9.9.9")}, nil
	}, dial: func(ctx context.Context, network, target string) (net.Conn, error) {
		if target != "1.1.1.1:443" {
			t.Fatal("direct pin changed")
		}
		return (&net.Dialer{}).DialContext(ctx, "tcp", server.Listener.Addr().String())
	}}
	endpoint, err := p.pin(context.Background(), nodeEgressEndpoint{url: "https://example.com/"})
	if err != nil {
		t.Fatal(err)
	}
	for _, address := range []string{"", socks.address} {
		if _, err := p.get(context.Background(), endpoint, address); err != nil {
			t.Fatal(err)
		}
	}
	request := <-socks.requests
	if lookups != 1 || request.AddressType != 1 || request.Host != "1.1.1.1" {
		t.Fatalf("paired endpoint was re-resolved: lookups=%d request=%+v", lookups, request)
	}
}

func TestNodeEgressPairCancellationSkipsRemainingMeasurements(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	calls := 0
	result := probeNodeEgressPair(ctx, "127.0.0.1:19181", func(context.Context, nodeEgressEndpoint, string) (string, error) {
		calls++
		cancel()
		return "8.8.8.8", nil
	})
	if calls != 1 || result.directIP != "" || result.proxyIP != "" || !errors.Is(result.directErr, context.Canceled) || !errors.Is(result.proxyErr, context.Canceled) {
		t.Fatalf("canceled pair continued or published an IP: calls=%d result=%+v", calls, result)
	}
}
