package dataplane

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/probecheck"
)

func nodeLANClientRequest() NodeLANHTTPSRequest {
	return NodeLANHTTPSRequest{
		RuntimeID: strings.Repeat("a", 64), Challenge: strings.Repeat("b", 64),
		URL: "https://example.com/health?q=original", Source: netip.MustParseAddr("192.168.1.25"), Destination: netip.MustParseAddr("1.1.1.1"),
	}
}

func nodeLANClientInterfaceOptions(source netip.Addr) nodeLANHTTPSOptions {
	return nodeLANHTTPSOptions{
		interfaces: func() ([]net.Interface, error) {
			return []net.Interface{{Index: 3, Name: "LAN-fixture", Flags: net.FlagUp}}, nil
		},
		addresses: func(net.Interface) ([]net.Addr, error) {
			return []net.Addr{&net.IPNet{IP: net.IP(source.AsSlice()), Mask: net.CIDRMask(source.BitLen(), source.BitLen())}}, nil
		},
	}
}

// A local TLS socket is mapped to the public pin and LAN source only inside
// this fixture. Production cannot inject or impersonate either socket address.
type nodeLANClientFixtureConn struct {
	net.Conn
	source, destination *net.TCPAddr
}

func (c nodeLANClientFixtureConn) LocalAddr() net.Addr  { return c.source }
func (c nodeLANClientFixtureConn) RemoteAddr() net.Addr { return c.destination }

func nodeLANClientTLSOptions(t *testing.T, request NodeLANHTTPSRequest, handler http.HandlerFunc) (nodeLANHTTPSOptions, <-chan string, *atomic.Int32) {
	t.Helper()
	server, config, names := newPinnedTLSFixture(t, handler)
	options := nodeLANClientInterfaceOptions(request.Source)
	options.roots = config.RootCAs
	calls := &atomic.Int32{}
	options.dial = func(ctx context.Context, dialer *net.Dialer, network, target string) (net.Conn, error) {
		calls.Add(1)
		family := "tcp4"
		if request.Destination.Is6() {
			family = "tcp6"
		}
		local, ok := dialer.LocalAddr.(*net.TCPAddr)
		deadline, bounded := ctx.Deadline()
		if !ok || !local.IP.Equal(net.IP(request.Source.AsSlice())) || local.Port != 0 || network != family || target != net.JoinHostPort(request.Destination.String(), "443") || dialer.Timeout <= 0 || dialer.Timeout > nodeLANHTTPSDeadline || !bounded || time.Until(deadline) > nodeLANHTTPSDeadline {
			return nil, errors.New("fixture received an unbound or unpinned transport")
		}
		conn, err := (&net.Dialer{Timeout: time.Second}).DialContext(ctx, "tcp", server.Listener.Addr().String())
		if err != nil {
			return nil, err
		}
		port := conn.LocalAddr().(*net.TCPAddr).Port
		return nodeLANClientFixtureConn{Conn: conn, source: &net.TCPAddr{IP: net.IP(request.Source.AsSlice()), Port: port}, destination: &net.TCPAddr{IP: net.IP(request.Destination.AsSlice()), Port: 443}}, nil
	}
	return options, names, calls
}

func TestNodeLANHTTPSProbePinsOriginalHTTPSFromExplicitSource(t *testing.T) {
	for _, family := range []string{"IPv4", "IPv6"} {
		t.Run(family, func(t *testing.T) {
			request := nodeLANClientRequest()
			if family == "IPv6" {
				request.Source, request.Destination = netip.MustParseAddr("fd00::25"), netip.MustParseAddr("2606:4700::1111")
			}
			requests := make(chan *http.Request, 1)
			body := "service reached"
			options, names, calls := nodeLANClientTLSOptions(t, request, func(w http.ResponseWriter, r *http.Request) {
				requests <- r.Clone(context.Background())
				w.Header().Set("Content-Type", "text/plain")
				_, _ = io.WriteString(w, body)
			})
			result, err := runNodeLANHTTPSProbe(context.Background(), request, options)
			if err != nil || !result.ServiceAccepted || result.HTTPStatus != 200 || calls.Load() != 1 {
				t.Fatalf("real local TLS probe failed: %+v %v", result, err)
			}
			observed := <-requests
			if observed.Host != "example.com" || observed.URL.String() != "/health?q=original" || <-names != "example.com" {
				t.Fatal("original Host/SNI/request path was replaced by the transport pin")
			}
			if observed.Header.Get("Authorization") != "" || observed.Header.Get("Proxy-Authorization") != "" || observed.Header.Get("X-RAZVILKA-Challenge") != "" {
				t.Fatal("private join metadata was sent to the service")
			}
			if result.RuntimeID != request.RuntimeID || result.Challenge != request.Challenge || result.URL != request.URL || result.Source.Addr() != request.Source || result.Source.Port() == 0 || result.Destination != netip.AddrPortFrom(request.Destination, 443) || result.Interface != "LAN-fixture" || result.InterfaceIndex != 3 || result.StartedAt.IsZero() || result.FinishedAt.Before(result.StartedAt) {
				t.Fatalf("result did not retain its exact connection/join metadata: %+v", result)
			}
			digest := sha256.Sum256([]byte(body))
			if result.BodyBytes != len(body) || result.BodySHA256 != hex.EncodeToString(digest[:]) {
				t.Fatal("accepted response sample was not bounded and fingerprinted")
			}
		})
	}
}

func TestNodeLANHTTPSProbeIgnoresEnvironmentProxies(t *testing.T) {
	proxyCalls := &atomic.Int32{}
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { proxyCalls.Add(1); w.WriteHeader(http.StatusBadGateway) }))
	defer proxy.Close()
	t.Setenv("HTTPS_PROXY", proxy.URL)
	t.Setenv("https_proxy", proxy.URL)
	t.Setenv("ALL_PROXY", proxy.URL)
	t.Setenv("NO_PROXY", "")
	request := nodeLANClientRequest()
	options, _, calls := nodeLANClientTLSOptions(t, request, func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "service reached") })
	result, err := runNodeLANHTTPSProbe(context.Background(), request, options)
	if err != nil || !result.ServiceAccepted || calls.Load() != 1 || proxyCalls.Load() != 0 {
		t.Fatalf("environment proxy changed direct pinned request: %+v %v", result, err)
	}
}

func TestNodeLANHTTPSProbeUsesStrictServiceResponseWithoutRedirects(t *testing.T) {
	for _, scenario := range []struct {
		name   string
		status int
		body   string
		accept bool
	}{
		{name: "204", status: http.StatusNoContent, accept: true},
		{name: "403", status: http.StatusForbidden, body: "forbidden"},
		{name: "451", status: http.StatusUnavailableForLegalReasons},
		{name: "429", status: http.StatusTooManyRequests},
		{name: "200-block-page", status: http.StatusOK, body: "<html>Доступ к информационному ресурсу ограничен</html>"},
		{name: "same-origin-redirect", status: http.StatusFound},
		{name: "500", status: http.StatusInternalServerError},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			request := nodeLANClientRequest()
			requests := &atomic.Int32{}
			options, _, calls := nodeLANClientTLSOptions(t, request, func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				w.Header().Set("Content-Type", "text/html")
				if scenario.status == http.StatusFound {
					w.Header().Set("Location", "https://example.com/final")
				}
				w.WriteHeader(scenario.status)
				_, _ = io.WriteString(w, scenario.body)
			})
			result, err := runNodeLANHTTPSProbe(context.Background(), request, options)
			if (err == nil) != scenario.accept || result.ServiceAccepted != scenario.accept || result.HTTPStatus != scenario.status || requests.Load() != 1 || calls.Load() != 1 {
				t.Fatalf("HTTP acceptance was widened: %+v err=%v requests=%d calls=%d", result, err, requests.Load(), calls.Load())
			}
			if !scenario.accept && (result.BodySHA256 != "" || result.BodyBytes != 0) {
				t.Fatal("failed response acquired accepted body evidence")
			}
		})
	}
}

func TestNodeLANHTTPSProbeRejectsBadMetadataBeforeLocalOrNetworkWork(t *testing.T) {
	for _, scenario := range []struct {
		name   string
		change func(*NodeLANHTTPSRequest)
	}{
		{name: "empty-runtime", change: func(r *NodeLANHTTPSRequest) { r.RuntimeID = "" }},
		{name: "short-runtime", change: func(r *NodeLANHTTPSRequest) { r.RuntimeID = strings.Repeat("a", 63) }},
		{name: "uppercase-runtime", change: func(r *NodeLANHTTPSRequest) { r.RuntimeID = strings.Repeat("A", 64) }},
		{name: "runtime-suffix", change: func(r *NodeLANHTTPSRequest) { r.RuntimeID += "x" }},
		{name: "empty-challenge", change: func(r *NodeLANHTTPSRequest) { r.Challenge = "" }},
		{name: "bad-challenge", change: func(r *NodeLANHTTPSRequest) { r.Challenge = strings.Repeat("g", 64) }},
		{name: "prefixed-challenge", change: func(r *NodeLANHTTPSRequest) { r.Challenge = "sha256:" + r.Challenge }},
		{name: "HTTP", change: func(r *NodeLANHTTPSRequest) { r.URL = "http://example.com/" }},
		{name: "auth-URL", change: func(r *NodeLANHTTPSRequest) { r.URL = "https://user:secret@example.com/" }},
		{name: "non443", change: func(r *NodeLANHTTPSRequest) { r.URL = "https://example.com:444/" }},
		{name: "fragment", change: func(r *NodeLANHTTPSRequest) { r.URL = "https://example.com/#secret" }},
		{name: "local-URL", change: func(r *NodeLANHTTPSRequest) { r.URL = "https://example.lan/" }},
		{name: "literal-pin-mismatch", change: func(r *NodeLANHTTPSRequest) { r.URL = "https://9.9.9.9/" }},
		{name: "URL-bound", change: func(r *NodeLANHTTPSRequest) { r.URL += strings.Repeat("x", 4097) }},
		{name: "invalid-pin", change: func(r *NodeLANHTTPSRequest) { r.Destination = netip.Addr{} }},
		{name: "private-pin", change: func(r *NodeLANHTTPSRequest) { r.Destination = netip.MustParseAddr("10.0.0.1") }},
		{name: "special-pin", change: func(r *NodeLANHTTPSRequest) { r.Destination = netip.MustParseAddr("192.0.2.1") }},
		{name: "mapped-pin", change: func(r *NodeLANHTTPSRequest) { r.Destination = netip.MustParseAddr("::ffff:1.1.1.1") }},
		{name: "zoned-pin", change: func(r *NodeLANHTTPSRequest) { r.Destination = netip.MustParseAddr("2606:4700::1111%fixture") }},
		{name: "loopback-source", change: func(r *NodeLANHTTPSRequest) { r.Source = netip.MustParseAddr("127.0.0.1") }},
		{name: "unspecified-source", change: func(r *NodeLANHTTPSRequest) { r.Source = netip.MustParseAddr("0.0.0.0") }},
		{name: "mapped-source", change: func(r *NodeLANHTTPSRequest) { r.Source = netip.MustParseAddr("::ffff:192.168.1.25") }},
		{name: "source-family", change: func(r *NodeLANHTTPSRequest) { r.Source = netip.MustParseAddr("fd00::25") }},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			request := nodeLANClientRequest()
			scenario.change(&request)
			work := &atomic.Int32{}
			options := nodeLANHTTPSOptions{
				interfaces: func() ([]net.Interface, error) { work.Add(1); return nil, nil },
				dial:       func(context.Context, *net.Dialer, string, string) (net.Conn, error) { work.Add(1); return nil, nil },
			}
			result, err := runNodeLANHTTPSProbe(context.Background(), request, options)
			if err == nil || result.ServiceAccepted || work.Load() != 0 || result.RuntimeID != "" {
				t.Fatalf("bad metadata reached local/network work: %+v %v work=%d", result, err, work.Load())
			}
		})
	}
}

func TestNodeLANHTTPSProbeRequiresActualAssignedUpNonLoopbackSource(t *testing.T) {
	request := nodeLANClientRequest()
	for _, scenario := range []string{"not-assigned", "down", "loopback", "ambiguous", "interface-error", "address-error", "interface-bound", "address-bound"} {
		t.Run(scenario, func(t *testing.T) {
			options := nodeLANClientInterfaceOptions(request.Source)
			original := options.interfaces
			switch scenario {
			case "not-assigned":
				options = nodeLANClientInterfaceOptions(netip.MustParseAddr("192.168.1.26"))
			case "down", "loopback", "ambiguous":
				options.interfaces = func() ([]net.Interface, error) {
					items, _ := original()
					if scenario == "down" {
						items[0].Flags = 0
					} else if scenario == "loopback" {
						items[0].Flags |= net.FlagLoopback
					} else {
						items = append(items, net.Interface{Index: 4, Name: "second", Flags: net.FlagUp})
					}
					return items, nil
				}
			case "interface-error":
				options.interfaces = func() ([]net.Interface, error) { return nil, errors.New("fixture") }
			case "address-error":
				options.addresses = func(net.Interface) ([]net.Addr, error) { return nil, errors.New("fixture") }
			case "interface-bound":
				options.interfaces = func() ([]net.Interface, error) { return make([]net.Interface, 257), nil }
			case "address-bound":
				options.addresses = func(net.Interface) ([]net.Addr, error) { return make([]net.Addr, 257), nil }
			}
			calls := &atomic.Int32{}
			options.dial = func(context.Context, *net.Dialer, string, string) (net.Conn, error) { calls.Add(1); return nil, nil }
			result, err := runNodeLANHTTPSProbe(context.Background(), request, options)
			if err == nil || result.ServiceAccepted || calls.Load() != 0 {
				t.Fatalf("invalid client source initiated HTTPS: %+v %v", result, err)
			}
		})
	}
}

func TestNodeLANHTTPSProbeRecordsAndChecksActualSocketAddresses(t *testing.T) {
	for _, scenario := range []string{"source", "destination", "port"} {
		t.Run(scenario, func(t *testing.T) {
			request := nodeLANClientRequest()
			requests := &atomic.Int32{}
			options, _, calls := nodeLANClientTLSOptions(t, request, func(w http.ResponseWriter, r *http.Request) { requests.Add(1) })
			dial := options.dial
			options.dial = func(ctx context.Context, d *net.Dialer, network, target string) (net.Conn, error) {
				conn, err := dial(ctx, d, network, target)
				if err != nil {
					return nil, err
				}
				mapped := conn.(nodeLANClientFixtureConn)
				switch scenario {
				case "source":
					mapped.source.IP = net.ParseIP("192.168.1.26")
				case "destination":
					mapped.destination.IP = net.ParseIP("9.9.9.9")
				case "port":
					mapped.destination.Port = 444
				}
				return mapped, nil
			}
			result, err := runNodeLANHTTPSProbe(context.Background(), request, options)
			if err == nil || result.ServiceAccepted || result.Source.IsValid() || result.Destination.IsValid() || calls.Load() != 1 || requests.Load() != 0 {
				t.Fatalf("mismatched actual socket was accepted: %+v %v", result, err)
			}
		})
	}
}

func TestNodeLANHTTPSProbeCannotBypassTLSVerification(t *testing.T) {
	for _, scenario := range []string{"untrusted-CA", "wrong-original-host"} {
		t.Run(scenario, func(t *testing.T) {
			request := nodeLANClientRequest()
			requests := &atomic.Int32{}
			options, _, calls := nodeLANClientTLSOptions(t, request, func(w http.ResponseWriter, r *http.Request) { requests.Add(1) })
			if scenario == "untrusted-CA" {
				options.roots = x509.NewCertPool()
			} else {
				request.URL = "https://wrong.invalid/"
			}
			result, err := runNodeLANHTTPSProbe(context.Background(), request, options)
			if err == nil || result.ServiceAccepted || result.HTTPStatus != 0 || calls.Load() != 1 || requests.Load() != 0 {
				t.Fatalf("unverified TLS reached service acceptance: %+v %v", result, err)
			}
		})
	}
}

func TestNodeLANHTTPSProbeFailsWhenSourceChangesDuringRequest(t *testing.T) {
	for _, scenario := range []string{"index", "down", "disappeared", "ambiguous"} {
		t.Run(scenario, func(t *testing.T) {
			request := nodeLANClientRequest()
			options, _, _ := nodeLANClientTLSOptions(t, request, func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "service reached") })
			checks := &atomic.Int32{}
			original := options.interfaces
			options.interfaces = func() ([]net.Interface, error) {
				items, err := original()
				if checks.Add(1) > 1 {
					switch scenario {
					case "index":
						items[0].Index++
					case "down":
						items[0].Flags = 0
					case "disappeared":
						items = nil
					case "ambiguous":
						items = append(items, net.Interface{Index: 4, Name: "second", Flags: net.FlagUp})
					}
				}
				return items, err
			}
			result, err := runNodeLANHTTPSProbe(context.Background(), request, options)
			if err == nil || result.ServiceAccepted || result.HTTPStatus != 200 || !result.Source.IsValid() || checks.Load() != 2 {
				t.Fatalf("changed local source acquired acceptance: %+v %v", result, err)
			}
		})
	}
}

func TestNodeLANHTTPSProbeRejectsOversizedHeadersAndInterruptedDeclaredBody(t *testing.T) {
	for _, scenario := range []string{"header-bound", "declared-body-short"} {
		t.Run(scenario, func(t *testing.T) {
			request := nodeLANClientRequest()
			options, _, _ := nodeLANClientTLSOptions(t, request, func(w http.ResponseWriter, r *http.Request) {
				if scenario == "header-bound" {
					w.Header().Set("X-Oversized", strings.Repeat("x", 32<<10))
				} else {
					w.Header().Set("Content-Length", "100")
				}
				_, _ = io.WriteString(w, "short")
			})
			result, err := runNodeLANHTTPSProbe(context.Background(), request, options)
			if err == nil || result.ServiceAccepted || result.BodySHA256 != "" || result.BodyBytes != 0 {
				t.Fatalf("unbounded or incomplete response acquired acceptance: %+v %v", result, err)
			}
		})
	}
}

func TestNodeLANHTTPSProbeCancellationAndBoundedBody(t *testing.T) {
	t.Run("already-canceled", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		result, err := RunNodeLANHTTPSProbe(ctx, nodeLANClientRequest())
		if !errors.Is(err, context.Canceled) || result.ServiceAccepted || result.RuntimeID != "" {
			t.Fatalf("canceled production request did work: %+v %v", result, err)
		}
		if _, err := RunNodeLANHTTPSProbe(nil, nodeLANClientRequest()); err == nil {
			t.Fatal("nil production context accepted")
		}
	})
	t.Run("dial-canceled", func(t *testing.T) {
		request := nodeLANClientRequest()
		options := nodeLANClientInterfaceOptions(request.Source)
		started := make(chan struct{})
		options.dial = func(ctx context.Context, d *net.Dialer, network, target string) (net.Conn, error) {
			close(started)
			deadline, ok := ctx.Deadline()
			if !ok || time.Until(deadline) > 5*time.Second {
				return nil, errors.New("socket dial lost its deadline")
			}
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
		result, err := runNodeLANHTTPSProbe(ctx, request, options)
		if !errors.Is(err, context.Canceled) || result.ServiceAccepted || result.Source.IsValid() {
			t.Fatalf("in-progress dial outlived caller cancellation: %+v %v", result, err)
		}
	})
	t.Run("TLS-canceled", func(t *testing.T) {
		request := nodeLANClientRequest()
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
		options := nodeLANClientInterfaceOptions(request.Source)
		options.dial = func(ctx context.Context, d *net.Dialer, network, target string) (net.Conn, error) {
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
		result, err := runNodeLANHTTPSProbe(ctx, request, options)
		if !errors.Is(err, context.Canceled) || result.ServiceAccepted || result.HTTPStatus != 0 {
			t.Fatalf("unfinished TLS acquired acceptance: %+v %v", result, err)
		}
		select {
		case <-closed:
		case <-time.After(500 * time.Millisecond):
			t.Fatal("caller cancellation left its TLS socket open")
		}
	})
	t.Run("stream-canceled", func(t *testing.T) {
		request := nodeLANClientRequest()
		started := make(chan struct{})
		options, _, calls := nodeLANClientTLSOptions(t, request, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/plain")
			_, _ = io.WriteString(w, "incomplete")
			w.(http.Flusher).Flush()
			close(started)
			<-r.Context().Done()
		})
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		go func() { <-started; cancel() }()
		result, err := runNodeLANHTTPSProbe(ctx, request, options)
		if !errors.Is(err, context.Canceled) || result.ServiceAccepted || result.BodySHA256 != "" || calls.Load() != 1 {
			t.Fatalf("interrupted body became accepted evidence: %+v %v", result, err)
		}
	})
	t.Run("large-page", func(t *testing.T) {
		request := nodeLANClientRequest()
		options, _, _ := nodeLANClientTLSOptions(t, request, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/plain")
			_, _ = io.WriteString(w, strings.Repeat("x", probecheck.MaxBodyBytes*4))
		})
		result, err := runNodeLANHTTPSProbe(context.Background(), request, options)
		if err != nil || !result.ServiceAccepted || result.BodyBytes != probecheck.MaxBodyBytes {
			t.Fatalf("body sample exceeded its existing bound: %+v %v", result, err)
		}
	})
}
