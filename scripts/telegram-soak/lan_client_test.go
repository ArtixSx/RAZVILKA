package main

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func fixtureLANAddress(t *testing.T) netip.Addr {
	t.Helper()
	interfaces, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	for _, iface := range interfaces {
		addresses, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, value := range addresses {
			prefix, err := netip.ParsePrefix(value.String())
			if err == nil && lanAddressPresent(prefix.Addr()) {
				return prefix.Addr()
			}
		}
	}
	t.Skip("local socket fixtures require an up nonloopback IPv4 interface")
	return netip.Addr{}
}

func absentLANAddress(t *testing.T) netip.Addr {
	t.Helper()
	for last := byte(1); last < 255; last++ {
		address := netip.AddrFrom4([4]byte{192, 0, 2, last})
		if !lanAddressPresent(address) {
			return address
		}
	}
	t.Fatal("no absent documentation-range fixture address")
	return netip.Addr{}
}

func TestLANOptionsRefuseInvalidAddressesAndBothModes(t *testing.T) {
	for _, address := range []string{"", "localhost", "127.0.0.1", "0.0.0.0", "224.0.0.1", "255.255.255.255", "::1", "::ffff:192.168.1.100", "192.168.1.100/24", "vless://PRIVATE-KEY@private.invalid/"} {
		_, help, err := parseOptions([]string{"--lan-client", address})
		if err == nil || help || err.Error() != "invalid options" {
			t.Fatal("invalid local address accepted or echoed", err)
		}
	}
	for _, args := range [][]string{
		{}, {"--socks", "127.0.0.1:1080", "--lan-client", "192.168.1.100"},
		{"--socks=", "--lan-client", "192.168.1.100"}, {"--socks", "127.0.0.1:1080", "--lan-client="},
	} {
		if _, _, err := parseOptions(args); err == nil {
			t.Fatal("missing or mutually exclusive modes accepted")
		}
	}
	parsed, help, err := parseOptions([]string{"--lan-client", "192.168.1.100"})
	if err != nil || help || parsed.SOCKS != "" || parsed.LANClient.String() != "192.168.1.100" || parsed.Duration != time.Hour {
		t.Fatal("LAN CLI did not preserve the finite defaults", err)
	}
	address := absentLANAddress(t)
	o := fixtureOptions("")
	o.LANClient = address
	r, err := observe(context.Background(), o, nil)
	if err != nil || r.Initial.OK || r.Initial.Code != "lan_client_address_unavailable" || r.Attempts != 0 || r.ExitCode != 1 || r.WindowCompleted {
		t.Fatal("absent local address opened a sampling window", r, err)
	}
	if _, err := newLANDialer(address); err == nil {
		t.Fatal("absent source address acquired a dialer")
	}
	o.SOCKS = "127.0.0.1:1080"
	if o.validate() == nil {
		t.Fatal("structured options accepted both modes")
	}
}

func fixtureLANListener(t *testing.T, address netip.Addr) *net.TCPListener {
	t.Helper()
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IP(address.AsSlice())})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	return listener
}

func assertNoFixtureConnection(t *testing.T, listener *net.TCPListener) {
	t.Helper()
	_ = listener.SetDeadline(time.Now().Add(30 * time.Millisecond))
	conn, err := listener.Accept()
	if conn != nil {
		_ = conn.Close()
		t.Fatal("unexpected fallback socket")
	}
	var timeout net.Error
	if !errors.As(err, &timeout) || !timeout.Timeout() {
		t.Fatal("fixture absence check failed", err)
	}
}

func TestLANDialUsesActualSourceAndFailedBindNeverFallsBack(t *testing.T) {
	address := fixtureLANAddress(t)
	backend := fixtureLANListener(t, address)
	proxy := fixtureLANListener(t, address)
	for _, key := range []string{"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"} {
		t.Setenv(key, "http://"+proxy.Addr().String())
	}
	t.Setenv("NO_PROXY", "")
	o := fixtureOptions("")
	o.LANClient = address
	selected, err := newOutboundDialer(o)
	if err != nil {
		t.Fatal(err)
	}
	dialer, ok := selected.(*lanDialer)
	if !ok {
		t.Fatal("LAN mode did not select the bound system dialer")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	conn, err := dialer.DialContext(ctx, "tcp", backend.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = backend.SetDeadline(time.Now().Add(time.Second))
	accepted, err := backend.AcceptTCP()
	if err != nil {
		t.Fatal(err)
	}
	defer accepted.Close()
	if conn.LocalAddr().(*net.TCPAddr).IP.String() != address.String() || accepted.RemoteAddr().(*net.TCPAddr).IP.String() != address.String() {
		t.Fatal("source address was not bound on the actual fixture socket")
	}
	// Occupy the chosen source port to make the operating system reject bind.
	// Production leaves the source port at zero; only this private test changes it.
	reserved := fixtureLANListener(t, address)
	dialer.socket.LocalAddr = reserved.Addr()
	failed, err := dialer.DialContext(ctx, "tcp", backend.Addr().String())
	if failed != nil {
		_ = failed.Close()
	}
	if err == nil || failed != nil {
		t.Fatal("occupied source port did not fail bind")
	}
	assertNoFixtureConnection(t, backend)
	assertNoFixtureConnection(t, proxy)
}

// Only fixed production targets are mapped, and every mapped socket still
// uses the real production LAN dialer and its LocalAddr. No external dial occurs.
type mappedLANDialer struct {
	bound   *lanDialer
	https   string
	mtproto string
	targets chan string
}

func (d *mappedLANDialer) DialContext(ctx context.Context, network, target string) (net.Conn, error) {
	if network != "tcp" {
		return nil, errors.New("unexpected fixture network")
	}
	var local string
	switch target {
	case telegramHost + ":443", "8.8.8.8:443":
		local = d.https
	case qaMTEndpoint:
		local = d.mtproto
	default:
		return nil, errors.New("unexpected fixture target")
	}
	d.targets <- target
	return d.bound.DialContext(ctx, network, local)
}

func fixtureMappedLANDialer(t *testing.T, address netip.Addr, https, mtproto string) *mappedLANDialer {
	t.Helper()
	bound, err := newLANDialer(address)
	if err != nil {
		t.Fatal(err)
	}
	return &mappedLANDialer{bound: bound, https: https, mtproto: mtproto, targets: make(chan string, 16)}
}

func TestLANHTTPSAndMTProtoKeepFixedTargetsTLSAndModeSpecificReport(t *testing.T) {
	address := fixtureLANAddress(t)
	proxy := fixtureLANListener(t, address)
	t.Setenv("HTTPS_PROXY", "http://"+proxy.Addr().String())
	t.Setenv("ALL_PROXY", "socks5://"+proxy.Addr().String())
	server, roots := fixtureTLS(t, telegramHost, func(w http.ResponseWriter, r *http.Request) {
		if r.Host != telegramHost || r.TLS.ServerName != telegramHost || r.URL.Path != "/" || !strings.HasPrefix(r.RemoteAddr, address.String()+":") {
			t.Error("LAN source or original TLS/HTTP identity changed")
		}
		_, _ = io.WriteString(w, "Telegram local fixture")
	}, net.JoinHostPort(address.String(), "0"))
	listener := fixtureLANListener(t, address)
	done := make(chan error, 1)
	go func() {
		_ = listener.SetDeadline(time.Now().Add(time.Second))
		conn, err := listener.AcceptTCP()
		if err != nil {
			done <- err
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(time.Second))
		var request [42]byte
		if _, err = io.ReadFull(conn, request[:]); err == nil {
			if request[0] != 0xef || request[1] != 10 || binary.LittleEndian.Uint32(request[22:26]) != qaMTReqPQ || conn.RemoteAddr().(*net.TCPAddr).IP.String() != address.String() {
				err = errors.New("unexpected local MTProto request/source")
			} else {
				var nonce [16]byte
				copy(nonce[:], request[26:])
				frame := qaMTPacket(nonce, time.Now())
				_, err = conn.Write(append([]byte{byte(len(frame) / 4)}, frame...))
			}
		}
		done <- err
	}()
	o, help, err := parseOptions([]string{"--lan-client", address.String(), "-mtproto", "-duration", "3.2s", "-probe-timeout", "100ms", "-control-timeout", "100ms", "-interval", "1s", "-telegram-ip", "8.8.8.8"})
	if err != nil || help {
		t.Fatal("valid LAN CLI rejected", err)
	}
	dialer := fixtureMappedLANDialer(t, address, server.Listener.Addr().String(), listener.Addr().String())
	r, err := observeWithDialer(context.Background(), o, roots, dialer)
	if err != nil || r.ExitCode != 0 || !r.WindowCompleted || r.Attempts != 1 || r.Accepted != 1 || r.Protocol == nil || r.Protocol.Replies != 1 || r.SamplingElapsedSeconds < o.Duration.Seconds() {
		t.Fatal("local LAN sampling/protocol failed", r, err)
	}
	if r.ConnectionMode != "lan-client" || r.LANClient != address.String() || r.Endpoint != "" || r.Initial.Code != "lan_client_address_present" || r.Final.Code != "lan_client_address_present" || !r.Initial.OK || !r.Final.OK || !strings.Contains(r.Protocol.Scope, "not proxy evidence") {
		t.Fatal("LAN observation mislabeled as SOCKS/path evidence", r)
	}
	encoded, err := json.Marshal(r)
	if err != nil || strings.Contains(string(encoded), "loopback_socks_endpoint") || !strings.Contains(string(encoded), "not proxy evidence") || !strings.Contains(string(encoded), "iptables counters") {
		t.Fatal("report omitted LAN limitations or included a SOCKS endpoint")
	}
	if len(dialer.targets) != 2 || <-dialer.targets != "8.8.8.8:443" || <-dialer.targets != qaMTEndpoint {
		t.Fatal("fixed targets changed, retried or skipped")
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	assertNoFixtureConnection(t, proxy)
}

func TestLANPartialOrCanceledSamplingNeverPasses(t *testing.T) {
	address := fixtureLANAddress(t)
	for _, mode := range []string{"canceled", "parent_deadline"} {
		t.Run(mode, func(t *testing.T) {
			var cancel context.CancelFunc
			served := make(chan struct{}, 1)
			server, roots := fixtureTLS(t, telegramHost, func(w http.ResponseWriter, _ *http.Request) {
				select {
				case served <- struct{}{}:
				default:
				}
				_, _ = io.WriteString(w, "local fixture")
				if mode == "canceled" {
					cancel()
				}
			}, net.JoinHostPort(address.String(), "0"))
			o := fixtureOptions("")
			o.LANClient, o.Duration = address, time.Second
			o.ProbeTimeout, o.ControlTimeout = 500*time.Millisecond, 500*time.Millisecond
			dialer := fixtureMappedLANDialer(t, address, server.Listener.Addr().String(), "")
			// Fixture setup and Windows address inventory must not turn the
			// explicit cancellation case into an unrelated parent deadline.
			var ctx context.Context
			if mode == "canceled" {
				ctx, cancel = context.WithCancel(context.Background())
			} else {
				ctx, cancel = context.WithTimeout(context.Background(), 250*time.Millisecond)
			}
			defer cancel()
			r, err := observeWithDialer(ctx, o, roots, dialer)
			if err != nil || r.ExitCode == 0 || r.WindowCompleted || r.Outcome != mode || r.SamplingElapsedSeconds >= o.Duration.Seconds() || r.Final.Code != "not_attempted_parent_cancellation" || len(dialer.targets) != 1 {
				t.Fatal("partial LAN sampling became PASS or retried", r, err)
			}
			if len(served) != 1 || mode == "parent_deadline" && (r.Accepted != 1 || !errors.Is(ctx.Err(), context.DeadlineExceeded)) {
				t.Fatal("partial-window test did not reach its HTTPS fixture before cancellation/deadline", r)
			}
		})
	}
}

func TestLANHTTPSRefusesTLSOverrideAndChangedTargets(t *testing.T) {
	address := fixtureLANAddress(t)
	o := fixtureOptions("")
	o.LANClient = address
	if _, err := newHTTPSProber(o, &tls.Config{InsecureSkipVerify: true}); err == nil {
		t.Fatal("LAN TLS verification override accepted")
	}
	p, err := newHTTPSProber(o, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer p.transport.CloseIdleConnections()
	if p.transport.Proxy != nil {
		t.Fatal("LAN mode installed an environment proxy")
	}
	for _, target := range []string{"private.invalid:443", telegramHost + ":80", qaMTEndpoint} {
		if conn, err := p.transport.DialContext(context.Background(), "tcp", target); err == nil || conn != nil {
			t.Fatal("changed HTTPS target accepted")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	control := endpointControl(ctx, o)
	if control.OK || control.Code != "canceled" {
		t.Fatal("canceled address control accepted")
	}
}

func TestSOCKSReportStillNamesItsEndpointAndControls(t *testing.T) {
	server, roots := fixtureTLS(t, telegramHost, func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "local fixture") })
	socks := fixtureSOCKS(t, server.Listener.Addr().String(), "")
	r, err := observe(context.Background(), fixtureOptions(socks.address), roots)
	if err != nil || r.ExitCode != 0 || r.ConnectionMode != "socks" || r.Endpoint != socks.address || r.LANClient != "" || r.Initial.Code != "socks5_no_auth" || r.Final.Code != "socks5_no_auth" {
		t.Fatal("SOCKS report/control contract changed", r, err)
	}
}
