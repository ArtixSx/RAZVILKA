package routeprobe

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"reflect"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/engine"
	"github.com/ArtixSx/razvilka/internal/systemprobe"
)

func TestInterfaceProbeRouteMustMatchActualDestinationAndDevice(t *testing.T) {
	source := netip.MustParseAddr("192.168.9.2")
	destination := netip.MustParseAddr("93.184.216.34")
	for _, tc := range []struct {
		name string
		raw  string
		want bool
	}{
		{"stock", "93.184.216.34 from 192.168.9.2 via 192.168.9.1 dev eth3\n    cache", true},
		{"route-without-source-text", "93.184.216.34 dev eth3", true},
		{"different-dns-answer", "1.1.1.1 from 192.168.9.2 dev eth3", false},
		{"other-source", "93.184.216.34 from 192.168.9.3 dev eth3", false},
		{"tunnel-egress", "93.184.216.34 dev wg0", false},
		{"local-redirect", "local 93.184.216.34 dev eth3", false},
		{"ambiguous-egress", "93.184.216.34 dev eth3 dev wg0", false},
		{"extra-route", "93.184.216.34 dev eth3\n93.184.216.34 dev wg0", false},
		{"incomplete", "93.184.216.34 dev", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := interfaceProbeRouteMatches(tc.raw, "eth3", source, destination); got != tc.want {
				t.Errorf("matched=%v, want %v", got, tc.want)
			}
		})
	}
}

type interfaceProbeTestConn struct {
	net.Conn
	local, remote netip.AddrPort
	closed        bool
}

func (c *interfaceProbeTestConn) LocalAddr() net.Addr  { return net.TCPAddrFromAddrPort(c.local) }
func (c *interfaceProbeTestConn) RemoteAddr() net.Addr { return net.TCPAddrFromAddrPort(c.remote) }
func (c *interfaceProbeTestConn) Close() error {
	c.closed = true
	return nil
}

func TestInterfaceProbeChecksEachNumericPeerBeforeDialAndAfterward(t *testing.T) {
	source := netip.MustParseAddr("192.168.9.2")
	allowed := netip.MustParseAddrPort("93.184.216.34:443")
	disallowed := netip.MustParseAddrPort("1.1.1.1:443")
	connection := &interfaceProbeTestConn{local: netip.AddrPortFrom(source, 20013), remote: allowed}
	var lookedUp []netip.Addr
	attempts := 0
	current := func(_ context.Context, peer netip.Addr) error {
		lookedUp = append(lookedUp, peer)
		if peer == disallowed.Addr() {
			return errProbeInterfaceRoute
		}
		return nil
	}
	dial := func(_ context.Context, network, target string) (net.Conn, error) {
		attempts++
		if network != "tcp4" || target != allowed.String() {
			t.Fatalf("unexpected physical dial %s %s", network, target)
		}
		return connection, nil
	}
	checked := checkedInterfaceDial(source, current, dial)
	if conn, err := checked(context.Background(), "tcp4", allowed.String()); err != nil || conn != connection {
		t.Fatalf("matched peer refused: %v", err)
	}
	// A redirect or alternate DNS answer must go through the check again.
	if conn, err := checked(context.Background(), "tcp4", disallowed.String()); conn != nil || !errors.Is(err, errProbeInterfaceRoute) {
		t.Fatalf("unexpected egress for second peer: %v", err)
	}
	if attempts != 1 || !reflect.DeepEqual(lookedUp, []netip.Addr{allowed.Addr(), allowed.Addr(), disallowed.Addr()}) {
		t.Fatalf("looked up %v, physically dialed %d times", lookedUp, attempts)
	}

	connection.remote = disallowed
	if conn, err := checked(context.Background(), "tcp4", allowed.String()); conn != nil || !errors.Is(err, errProbeInterfaceRoute) || !connection.closed {
		t.Fatalf("wrong connected peer escaped: %v closed=%v", err, connection.closed)
	}
}

func TestInterfaceProbeClosesSocketAfterRouteDrift(t *testing.T) {
	source := netip.MustParseAddr("192.168.9.2")
	peer := netip.MustParseAddrPort("93.184.216.34:443")
	connection := &interfaceProbeTestConn{local: netip.AddrPortFrom(source, 20013), remote: peer}
	dialed := false
	checked := checkedInterfaceDial(source, func(context.Context, netip.Addr) error {
		if dialed {
			return errProbeInterfaceRoute
		}
		return nil
	}, func(context.Context, string, string) (net.Conn, error) {
		dialed = true
		return connection, nil
	})
	if conn, err := checked(context.Background(), "tcp4", peer.String()); conn != nil || !errors.Is(err, errProbeInterfaceRoute) || !connection.closed {
		t.Fatalf("connection from a changed route escaped: %v closed=%v", err, connection.closed)
	}
}

func TestInterfaceProbeJoinsCanceledDial(t *testing.T) {
	started := make(chan struct{})
	canceled := make(chan struct{})
	release := make(chan struct{})
	transport := interfaceProbeTransport{dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
		close(started)
		<-ctx.Done()
		close(canceled)
		<-release
		return nil, ctx.Err()
	}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	request, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://example.com", nil)
	finished := make(chan error, 1)
	go func() {
		_, err := transport.RoundTrip(request)
		finished <- err
	}()
	await := func(what string, done <-chan struct{}) {
		t.Helper()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatalf("timed out waiting for %s", what)
		}
	}
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
	}()
	await("dial", started)
	cancel()
	await("dial cancellation", canceled)
	select {
	case err := <-finished:
		t.Fatalf("request returned before its dial joined: %v", err)
	default:
	}
	close(release)
	select {
	case err := <-finished:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("expected request cancellation, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("request did not finish after dial joined")
	}
}

func TestInterfaceProbeUnconfirmedWhenNoHTTPResponse(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, errProbeInterfaceRoute
	})}
	service := catalog.Service{ID: "test", ProbeURL: "https://example.com/"}
	result := probeHTTP(context.Background(), client, service, "direct", interfaceProbeEvidence+"eth3", true)
	if result.RouteConfirmed || result.RouteProofError != "route-interface-unconfirmed" || result.Status != "not-ready" {
		t.Fatalf("unverified route treated as observed failure: %+v", result)
	}
}

func TestCanceledProbeSkipsSystemAndRuntimeDiscovery(t *testing.T) {
	m := New(nil)
	m.System = func() systemprobe.Snapshot { t.Fatal("read WAN after cancellation"); return systemprobe.Snapshot{} }
	m.Statuses = func() []engine.Status { t.Fatal("read engines after cancellation"); return nil }
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, route := range []string{"direct", "wireguard", "nfqws2"} {
		result := m.Probe(ctx, catalog.Service{ID: "test", ProbeURL: "https://example.com/"}, route)
		if result.RouteConfirmed || result.Detail != context.Canceled.Error() {
			t.Errorf("route %s: unexpected canceled result: %+v", route, result)
		}
	}
}
