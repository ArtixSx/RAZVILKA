package dataplane

import (
	"context"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"runtime"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/probecheck"
)

func nodeRouterFixtureRequest() nodeRouterHTTPSRequest {
	return nodeRouterHTTPSRequest{URL: "https://example.com/health?q=original", Interface: "rz-xray", IfIndex: 77,
		Source: netip.MustParseAddr("172.31.22.1"), Destination: netip.MustParseAddr("1.1.1.1")}
}

type nodeRouterFixtureRawConn struct{ err error }

func (r nodeRouterFixtureRawConn) Control(fn func(uintptr)) error {
	if r.err != nil {
		return r.err
	}
	fn(42)
	return nil
}
func (nodeRouterFixtureRawConn) Read(func(uintptr) bool) error {
	return errors.New("unused fixture raw read")
}
func (nodeRouterFixtureRawConn) Write(func(uintptr) bool) error {
	return errors.New("unused fixture raw write")
}

func nodeRouterFixtureOptions(request nodeRouterHTTPSRequest) nodeRouterHTTPSOptions {
	return nodeRouterHTTPSOptions{
		interfaces: func() ([]net.Interface, error) {
			return []net.Interface{{Name: request.Interface, Index: request.IfIndex, Flags: net.FlagUp}}, nil
		},
		addresses: func(net.Interface) ([]net.Addr, error) {
			return []net.Addr{&net.IPNet{IP: net.IP(request.Source.AsSlice()), Mask: net.CIDRMask(30, 32)}}, nil
		},
		bind: func(raw syscall.RawConn, name string) error {
			return nodeRouterCheckedSocketBinding(raw, name, func(fd int, value string) error {
				if fd != 42 || value != request.Interface {
					return errors.New("fixture socket set was not exact")
				}
				return nil
			}, func(fd int) (string, error) { return request.Interface, nil })
		},
	}
}

// Public literals/TUN source are mapped to one local TLS socket only through
// private fixtures; these tests do not claim native TUN traversal or a lease.
func nodeRouterTLSFixture(t *testing.T, request nodeRouterHTTPSRequest, handler http.HandlerFunc) (nodeRouterHTTPSOptions, <-chan string, *atomic.Int32) {
	t.Helper()
	server, config, names := newPinnedTLSFixture(t, handler)
	options := nodeRouterFixtureOptions(request)
	options.roots = config.RootCAs
	calls := &atomic.Int32{}
	options.dial = func(ctx context.Context, d *net.Dialer, network, target string) (net.Conn, error) {
		calls.Add(1)
		local, ok := d.LocalAddr.(*net.TCPAddr)
		deadline, bounded := ctx.Deadline()
		if !ok || !local.IP.Equal(net.IP(request.Source.AsSlice())) || local.Port != 0 || d.ControlContext == nil || network != "tcp4" || target != net.JoinHostPort(request.Destination.String(), "443") || d.Timeout > 4*time.Second || d.FallbackDelay >= 0 || d.MultipathTCP() || !bounded || time.Until(deadline) > 4*time.Second {
			return nil, errors.New("fixture received an unbound, fallback or unbudgeted dial")
		}
		if err := d.ControlContext(ctx, network, target, nodeRouterFixtureRawConn{}); err != nil {
			return nil, err
		}
		conn, err := (&net.Dialer{Timeout: time.Second}).DialContext(ctx, "tcp", server.Listener.Addr().String())
		if err != nil {
			return nil, err
		}
		return nodeLANClientFixtureConn{Conn: conn, source: &net.TCPAddr{IP: net.IP(request.Source.AsSlice()), Port: conn.LocalAddr().(*net.TCPAddr).Port}, destination: &net.TCPAddr{IP: net.IP(request.Destination.AsSlice()), Port: 443}}, nil
	}
	return options, names, calls
}

func TestNodeRouterHTTPSUsesExactSourceDevicePinTLSAndOrigin(t *testing.T) {
	request := nodeRouterFixtureRequest()
	requests := make(chan *http.Request, 1)
	options, names, calls := nodeRouterTLSFixture(t, request, func(w http.ResponseWriter, r *http.Request) {
		requests <- r.Clone(context.Background())
		_, _ = io.WriteString(w, "service reached")
	})
	controls := &atomic.Int32{}
	bind := options.bind
	options.bind = func(raw syscall.RawConn, name string) error { controls.Add(1); return bind(raw, name) }
	result, err := runNodeRouterHTTPSProbe(context.Background(), request, options)
	if err != nil || !result.ServiceAccepted || result.Origin != "router-owned-tun" || result.Interface != request.Interface || result.IfIndex != request.IfIndex || result.HTTPStatus != 200 || calls.Load() != 1 || controls.Load() != 1 {
		t.Fatalf("router socket contract failed: %+v %v", result, err)
	}
	observed := <-requests
	if observed.Host != "example.com" || observed.URL.String() != "/health?q=original" || <-names != "example.com" || observed.Header.Get("Authorization") != "" {
		t.Fatal("original TLS Host/SNI/request target was changed")
	}
	if result.Source.Addr() != request.Source || result.Source.Port() == 0 || result.Destination != netip.AddrPortFrom(request.Destination, 443) || result.StartedAt.IsZero() || result.FinishedAt.Before(result.StartedAt) || !nodeLANHash(result.BodySHA256) || result.BodyBytes != len("service reached") {
		t.Fatalf("observed socket/sample facts were not exact: %+v", result)
	}
}

func TestNodeRouterSocketBindingRequiresSuccessfulSetAndMatchingGet(t *testing.T) {
	for _, scenario := range []string{"ok", "set-error", "get-error", "get-mismatch", "raw-error"} {
		t.Run(scenario, func(t *testing.T) {
			sets, gets := 0, 0
			raw := nodeRouterFixtureRawConn{}
			if scenario == "raw-error" {
				raw.err = errors.New("fixture raw control failed")
			}
			err := nodeRouterCheckedSocketBinding(raw, "rz-xray", func(fd int, name string) error {
				sets++
				if fd != 42 || name != "rz-xray" || scenario == "set-error" {
					return errors.New("fixture set failed")
				}
				return nil
			}, func(fd int) (string, error) {
				gets++
				if scenario == "get-error" {
					return "", errors.New("fixture get failed")
				}
				if scenario == "get-mismatch" {
					return "eth-fixture", nil
				}
				return "rz-xray", nil
			})
			if (err == nil) != (scenario == "ok") || sets > 1 || gets > 1 || scenario == "set-error" && gets != 0 || scenario == "raw-error" && sets != 0 {
				t.Fatalf("socket set/get authority widened: err=%v sets=%d gets=%d", err, sets, gets)
			}
		})
	}
}

func TestNodeRouterHTTPSBindingFailureNeverFallsBack(t *testing.T) {
	request := nodeRouterFixtureRequest()
	requests := &atomic.Int32{}
	options, _, calls := nodeRouterTLSFixture(t, request, func(w http.ResponseWriter, r *http.Request) { requests.Add(1) })
	options.bind = func(syscall.RawConn, string) error { return errors.New("binding unavailable") }
	result, err := runNodeRouterHTTPSProbe(context.Background(), request, options)
	if !errors.Is(err, errNodeRouterHTTPSUnavailable) || result.ServiceAccepted || result.Source.IsValid() || calls.Load() != 1 || requests.Load() != 0 {
		t.Fatalf("binding failure acquired a fallback result: %+v %v", result, err)
	}
}

func TestNodeRouterHTTPSRefusesMissingControlAndSocketMismatch(t *testing.T) {
	for _, scenario := range []string{"control-not-invoked", "wrong-source", "wrong-destination"} {
		t.Run(scenario, func(t *testing.T) {
			request := nodeRouterFixtureRequest()
			requests := &atomic.Int32{}
			options, _, _ := nodeRouterTLSFixture(t, request, func(w http.ResponseWriter, r *http.Request) { requests.Add(1) })
			dial := options.dial
			options.dial = func(ctx context.Context, d *net.Dialer, network, target string) (net.Conn, error) {
				originalControl := d.ControlContext
				if scenario == "control-not-invoked" {
					d.ControlContext = func(context.Context, string, string, syscall.RawConn) error { return nil }
				}
				conn, err := dial(ctx, d, network, target)
				d.ControlContext = originalControl
				if err != nil {
					return nil, err
				}
				mapped := conn.(nodeLANClientFixtureConn)
				if scenario == "wrong-source" {
					mapped.source.IP = net.ParseIP("172.31.22.2")
				} else if scenario == "wrong-destination" {
					mapped.destination.IP = net.ParseIP("9.9.9.9")
				}
				return mapped, nil
			}
			result, err := runNodeRouterHTTPSProbe(context.Background(), request, options)
			if !errors.Is(err, errNodeRouterHTTPSUnavailable) || result.ServiceAccepted || result.HTTPStatus != 0 || requests.Load() != 0 {
				t.Fatalf("unchecked socket acquired HTTPS acceptance: %+v %v", result, err)
			}
		})
	}
}

func TestNodeRouterHTTPSIfindexAndAssignedSourceRemainExact(t *testing.T) {
	for _, scenario := range []string{"wrong-initial-name", "wrong-initial-index", "missing-source", "changed-before-control", "changed-after-binding", "changed-after-response"} {
		t.Run(scenario, func(t *testing.T) {
			request := nodeRouterFixtureRequest()
			options, _, calls := nodeRouterTLSFixture(t, request, func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "service reached") })
			checks, bindings := &atomic.Int32{}, &atomic.Int32{}
			interfaces, bind := options.interfaces, options.bind
			options.bind = func(raw syscall.RawConn, name string) error { bindings.Add(1); return bind(raw, name) }
			options.interfaces = func() ([]net.Interface, error) {
				items, err := interfaces()
				at := checks.Add(1)
				if scenario == "wrong-initial-name" {
					items[0].Name = "foreign"
				} else if scenario == "wrong-initial-index" || scenario == "changed-before-control" && at >= 2 || scenario == "changed-after-binding" && at >= 3 || scenario == "changed-after-response" && at >= 4 {
					items[0].Index++
				}
				return items, err
			}
			if scenario == "missing-source" {
				options.addresses = func(net.Interface) ([]net.Addr, error) { return nil, nil }
			}
			result, err := runNodeRouterHTTPSProbe(context.Background(), request, options)
			if !errors.Is(err, errNodeRouterHTTPSUnavailable) || result.ServiceAccepted || scenario == "changed-before-control" && bindings.Load() != 0 || strings.HasPrefix(scenario, "wrong-initial") && calls.Load() != 0 {
				t.Fatalf("source/device drift acquired acceptance: %+v %v checks=%d binds=%d", result, err, checks.Load(), bindings.Load())
			}
		})
	}
}

func TestNodeRouterHTTPSRejectsInvalidRequestBeforeAnyWork(t *testing.T) {
	for _, scenario := range []string{"bad-interface", "loopback-interface", "bad-index", "IPv6-source", "loopback-source", "mapped-source", "IPv6-pin", "private-pin", "mapped-pin", "auth-URL", "HTTP", "non443", "fragment", "literal-mismatch"} {
		t.Run(scenario, func(t *testing.T) {
			request := nodeRouterFixtureRequest()
			switch scenario {
			case "bad-interface":
				request.Interface = "rz-xray/foreign"
			case "loopback-interface":
				request.Interface = "lo"
			case "bad-index":
				request.IfIndex = 0
			case "IPv6-source":
				request.Source = netip.MustParseAddr("fd00::1")
			case "loopback-source":
				request.Source = netip.MustParseAddr("127.0.0.1")
			case "mapped-source":
				request.Source = netip.MustParseAddr("::ffff:172.31.22.1")
			case "IPv6-pin":
				request.Destination = netip.MustParseAddr("2606:4700::1111")
			case "private-pin":
				request.Destination = netip.MustParseAddr("10.0.0.1")
			case "mapped-pin":
				request.Destination = netip.MustParseAddr("::ffff:1.1.1.1")
			case "auth-URL":
				request.URL = "https://user:secret@example.com/"
			case "HTTP":
				request.URL = "http://example.com/"
			case "non443":
				request.URL = "https://example.com:444/"
			case "fragment":
				request.URL = "https://example.com/#secret"
			case "literal-mismatch":
				request.URL = "https://9.9.9.9/"
			}
			work := &atomic.Int32{}
			options := nodeRouterHTTPSOptions{bind: func(syscall.RawConn, string) error { work.Add(1); return nil }, interfaces: func() ([]net.Interface, error) { work.Add(1); return nil, nil }}
			result, err := runNodeRouterHTTPSProbe(context.Background(), request, options)
			if err == nil || result.ServiceAccepted || result.Origin != "" || work.Load() != 0 {
				t.Fatalf("invalid request reached OS work: %+v %v", result, err)
			}
		})
	}
}

func TestNodeRouterHTTPSSemanticsTLSBoundsAndNoProxy(t *testing.T) {
	for _, scenario := range []string{"403", "block-page", "redirect", "bad-TLS-root", "bad-TLS-host", "large-body", "short-declared-body", "large-header", "environment-proxy"} {
		t.Run(scenario, func(t *testing.T) {
			request := nodeRouterFixtureRequest()
			options, _, calls := nodeRouterTLSFixture(t, request, func(w http.ResponseWriter, r *http.Request) {
				switch scenario {
				case "403":
					w.WriteHeader(http.StatusForbidden)
				case "block-page":
					w.Header().Set("Content-Type", "text/html")
					_, _ = io.WriteString(w, "<html>Доступ к информационному ресурсу ограничен</html>")
				case "redirect":
					w.Header().Set("Location", "https://example.com/final")
					w.WriteHeader(http.StatusFound)
				case "large-body":
					_, _ = io.WriteString(w, strings.Repeat("x", probecheck.MaxBodyBytes*4))
				case "short-declared-body":
					w.Header().Set("Content-Length", "100")
					_, _ = io.WriteString(w, "short")
				case "large-header":
					w.Header().Set("X-Large", strings.Repeat("x", 32<<10))
					_, _ = io.WriteString(w, "service reached")
				default:
					_, _ = io.WriteString(w, "service reached")
				}
			})
			if scenario == "bad-TLS-root" {
				options.roots = x509.NewCertPool()
			} else if scenario == "bad-TLS-host" {
				request.URL = "https://wrong.invalid/"
			}
			proxyCalls := &atomic.Int32{}
			if scenario == "environment-proxy" {
				proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { proxyCalls.Add(1); w.WriteHeader(502) }))
				defer proxy.Close()
				t.Setenv("HTTPS_PROXY", proxy.URL)
				t.Setenv("ALL_PROXY", proxy.URL)
				t.Setenv("NO_PROXY", "")
			}
			result, err := runNodeRouterHTTPSProbe(context.Background(), request, options)
			accepted := scenario == "large-body" || scenario == "environment-proxy"
			if (err == nil) != accepted || result.ServiceAccepted != accepted || calls.Load() != 1 || proxyCalls.Load() != 0 || scenario == "large-body" && result.BodyBytes != probecheck.MaxBodyBytes {
				t.Fatalf("HTTPS semantic/TLS/boundary weakened: %+v %v", result, err)
			}
		})
	}
}

func TestNodeRouterHTTPSCallerCancelStopsPendingDialAndJoinsSocket(t *testing.T) {
	request := nodeRouterFixtureRequest()
	options := nodeRouterFixtureOptions(request)
	started, finished := make(chan struct{}), make(chan struct{})
	options.dial = func(ctx context.Context, d *net.Dialer, network, target string) (net.Conn, error) {
		defer close(finished)
		close(started)
		<-ctx.Done()
		return nil, ctx.Err()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	go func() {
		select {
		case <-started:
			cancel()
		case <-ctx.Done():
		}
	}()
	result, err := runNodeRouterHTTPSProbe(ctx, request, options)
	if !errors.Is(err, context.Canceled) || result.ServiceAccepted || result.Source.IsValid() {
		t.Fatalf("canceled dial acquired acceptance: %+v %v", result, err)
	}
	select {
	case <-finished:
	default:
		t.Fatal("probe returned before its canceled dial finished")
	}
}

func TestNodeRouterHTTPSCallerCancelClosesStalledTLSSocket(t *testing.T) {
	request := nodeRouterFixtureRequest()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	started, closed := make(chan struct{}), make(chan struct{})
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
		buffer := make([]byte, 4096)
		if n, _ := conn.Read(buffer); n > 0 {
			close(started)
		}
		_, _ = io.Copy(io.Discard, conn)
		close(closed)
	}()
	options := nodeRouterFixtureOptions(request)
	options.dial = func(ctx context.Context, d *net.Dialer, network, target string) (net.Conn, error) {
		if err := d.ControlContext(ctx, network, target, nodeRouterFixtureRawConn{}); err != nil {
			return nil, err
		}
		conn, err := (&net.Dialer{Timeout: time.Second}).DialContext(ctx, "tcp", listener.Addr().String())
		if err != nil {
			return nil, err
		}
		return nodeLANClientFixtureConn{Conn: conn, source: &net.TCPAddr{IP: net.IP(request.Source.AsSlice()), Port: conn.LocalAddr().(*net.TCPAddr).Port}, destination: &net.TCPAddr{IP: net.IP(request.Destination.AsSlice()), Port: 443}}, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	go func() {
		select {
		case <-started:
			cancel()
		case <-ctx.Done():
		}
	}()
	result, err := runNodeRouterHTTPSProbe(ctx, request, options)
	if !errors.Is(err, context.Canceled) || result.ServiceAccepted || result.HTTPStatus != 0 || result.BodySHA256 != "" {
		t.Fatalf("unfinished TLS acquired acceptance: %+v %v", result, err)
	}
	select {
	case <-closed:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("caller cancellation left its TLS socket open")
	}
}

func TestNodeRouterHTTPSCancelBodyAndNonLinuxProductionUnavailable(t *testing.T) {
	request := nodeRouterFixtureRequest()
	started := make(chan struct{})
	options, _, _ := nodeRouterTLSFixture(t, request, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "incomplete")
		w.(http.Flusher).Flush()
		close(started)
		<-r.Context().Done()
	})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	go func() {
		select {
		case <-started:
			cancel()
		case <-ctx.Done():
		}
	}()
	result, err := runNodeRouterHTTPSProbe(ctx, request, options)
	if !errors.Is(err, context.Canceled) || result.ServiceAccepted || result.BodySHA256 != "" {
		t.Fatalf("canceled stream acquired acceptance: %+v %v", result, err)
	}
	if runtime.GOOS != "linux" {
		result, err = probeNodeRouterHTTPS(context.Background(), request)
		if !errors.Is(err, errNodeRouterHTTPSUnavailable) || result.Origin != "" {
			t.Fatalf("non-Linux production silently bypassed device binding: %+v %v", result, err)
		}
	}
}
