package usquediag

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// This is only a localhost Transport/SOCKS deadline regression. The proxy
// terminates fixture TLS instead of contacting a public peer. Its ephemeral CA
// is assigned only to fixture transport instances. No USQUE/WARP/UDP/account
// fact or production certificate acceptance is established by these results.
func TestNativeOwnedHTTPDialContextHarness(t *testing.T) {
	if os.Getenv("RAZVILKA_NATIVE_CLOUD_OWNED_DIAL") != "1" {
		t.Skip("requires explicit localhost owned HTTP dial opt-in")
	}
	for _, kind := range []string{"HTTPS", "DoH"} {
		t.Run(kind, func(t *testing.T) {
			for _, mode := range []string{"success", "missing-marker", "greeting-cancel", "CONNECT-cancel", "greeting-deadline", "CONNECT-deadline", "TLS-name", "TLS-trust"} {
				t.Run(mode, func(t *testing.T) {
					ownedDialNativeCase(t, kind, mode)
				})
			}
		})
	}
	t.Run("DoH-three-second-child-overwrites-outer-window", func(t *testing.T) {
		ownedDialNativeCase(t, "DoH", "DNS-window")
	})
}

func ownedDialFixtureCertificate(t *testing.T, wrongName bool) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	names := []string{"example.com", "cloudflare-dns.com"}
	if wrongName {
		names = []string{"wrong.example.com"}
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: names[0]}, DNSNames: names, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(certificate)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, roots
}

type ownedDialFixtureResult struct {
	literal    netip.AddrPort
	serverName string
	err        error
}

type ownedDialFixtureProxy struct {
	listener           net.Listener
	endpoint           netip.AddrPort
	mode               string
	certificate        tls.Certificate
	ready              chan struct{}
	closed             chan error
	result             chan ownedDialFixtureResult
	done               chan struct{}
	accepted, connects atomic.Int32
	mu                 sync.Mutex
	connections        []net.Conn
	workers            sync.WaitGroup
}

func newOwnedDialFixtureProxy(t *testing.T, mode string, certificate tls.Certificate) *ownedDialFixtureProxy {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	endpoint, err := netip.ParseAddrPort(listener.Addr().String())
	if err != nil {
		listener.Close()
		t.Fatal(err)
	}
	f := &ownedDialFixtureProxy{listener: listener, endpoint: endpoint, mode: mode, certificate: certificate, ready: make(chan struct{}, 4), closed: make(chan error, 4), result: make(chan ownedDialFixtureResult, 4), done: make(chan struct{})}
	go func() {
		defer close(f.done)
		for {
			connection, err := listener.Accept()
			if err != nil {
				return
			}
			f.accepted.Add(1)
			f.mu.Lock()
			f.connections = append(f.connections, connection)
			f.mu.Unlock()
			f.workers.Add(1)
			go func() { defer f.workers.Done(); f.serve(connection) }()
		}
	}()
	t.Cleanup(func() {
		listener.Close()
		select {
		case <-f.done:
		case <-time.After(time.Second):
			t.Error("fixture accept loop did not stop")
		}
		f.mu.Lock()
		for _, connection := range f.connections {
			connection.Close()
		}
		f.mu.Unlock()
		joined := make(chan struct{})
		go func() { f.workers.Wait(); close(joined) }()
		select {
		case <-joined:
		case <-time.After(time.Second):
			t.Error("fixture SOCKS/TLS workers did not stop")
		}
	})
	return f
}

func (f *ownedDialFixtureProxy) serve(connection net.Conn) {
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(5 * time.Second))
	result := ownedDialFixtureResult{}
	defer func() { f.result <- result }()
	var greeting [3]byte
	if _, result.err = io.ReadFull(connection, greeting[:]); result.err != nil {
		return
	}
	if greeting != [3]byte{5, 1, 0} {
		result.err = errors.New("invalid fixture SOCKS greeting")
		return
	}
	if f.mode == "greeting-cancel" || f.mode == "greeting-deadline" || f.mode == "DNS-window" {
		f.ready <- struct{}{}
		var b [1]byte
		_, result.err = connection.Read(b[:])
		f.closed <- result.err
		return
	}
	if _, result.err = connection.Write([]byte{5, 0}); result.err != nil {
		return
	}
	var header [4]byte
	if _, result.err = io.ReadFull(connection, header[:]); result.err != nil {
		return
	}
	if header[0] != 5 || header[1] != 1 || header[2] != 0 || header[3] != 1 && header[3] != 4 {
		result.err = errors.New("fixture CONNECT was not literal")
		return
	}
	size := 4
	if header[3] == 4 {
		size = 16
	}
	address := make([]byte, 1+size+2)
	address[0] = header[3]
	if _, result.err = io.ReadFull(connection, address[1:]); result.err != nil {
		return
	}
	result.literal, result.err = ownedSOCKSLiteral(address)
	if result.err != nil {
		return
	}
	f.connects.Add(1)
	if f.mode == "CONNECT-cancel" || f.mode == "CONNECT-deadline" {
		f.ready <- struct{}{}
		var b [1]byte
		_, result.err = connection.Read(b[:])
		f.closed <- result.err
		return
	}
	if _, result.err = connection.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 1}); result.err != nil {
		return
	}
	secure := tls.Server(connection, &tls.Config{Certificates: []tls.Certificate{f.certificate}, MinVersion: tls.VersionTLS12})
	if result.err = secure.Handshake(); result.err != nil {
		return
	}
	result.serverName = secure.ConnectionState().ServerName
	request, err := http.ReadRequest(bufio.NewReader(secure))
	if err != nil {
		result.err = err
		return
	}
	defer request.Body.Close()
	body := []byte("fixture body")
	media := "text/plain"
	if request.URL.Path == "/dns-query" {
		wire, err := io.ReadAll(io.LimitReader(request.Body, 4097))
		if err != nil {
			result.err = err
			return
		}
		var query dnsmessage.Message
		if err := query.Unpack(wire); err != nil || len(query.Questions) != 1 {
			result.err = errors.New("invalid fixture DoH query")
			return
		}
		reply := dnsmessage.Message{Header: dnsmessage.Header{ID: query.ID, Response: true, RecursionDesired: true, RecursionAvailable: true}, Questions: query.Questions, Answers: []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: query.Questions[0].Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 1}, Body: &dnsmessage.AResource{A: [4]byte{1, 1, 1, 1}}}}}
		body, result.err = reply.Pack()
		if result.err != nil {
			return
		}
		media = "application/dns-message"
	}
	response := &http.Response{StatusCode: http.StatusOK, ProtoMajor: 1, ProtoMinor: 1, Header: http.Header{"Content-Type": []string{media}}, Body: io.NopCloser(bytes.NewReader(body)), ContentLength: int64(len(body)), Close: true}
	result.err = response.Write(secure)
}

func ownedDialNativeCase(t *testing.T, kind, mode string) {
	t.Helper()
	certificate, roots := ownedDialFixtureCertificate(t, mode == "TLS-name")
	fixture := newOwnedDialFixtureProxy(t, mode, certificate)
	window := 5 * time.Second
	if mode == "greeting-deadline" || mode == "CONNECT-deadline" {
		window = 150 * time.Millisecond
	}
	if mode == "DNS-window" {
		window = 20 * time.Second
	}
	original := newOwnedProbeTargetFixture(t, nil)
	owner, stopOwner := context.WithTimeout(original.ctx, 20*time.Second)
	defer stopOwner()
	ctx, cancel := context.WithTimeout(owner, window)
	defer cancel()
	sockets := &probeSockets{}
	defer sockets.close()
	// The socket owner remains live when this request is canceled. This makes
	// handshake cancellation prove per-request Close rather than global cleanup.
	stop := context.AfterFunc(owner, sockets.close)
	defer stop()
	resolverCalls := atomic.Int32{}
	transport := ownedHTTPTransport(fixture.endpoint, sockets, 5*time.Second, func(context.Context, string) ([]netip.Addr, error) {
		resolverCalls.Add(1)
		return []netip.Addr{netip.MustParseAddr("1.1.1.1")}, nil
	})
	url, wantServerName := "https://example.com/proof", "example.com"
	if kind == "DoH" {
		transport = ownedDoHTransport(fixture.endpoint, sockets, 5*time.Second)
		url, wantServerName = ownedDoHURL, "cloudflare-dns.com"
	}
	if transport.Proxy != nil || transport.TLSClientConfig.RootCAs != nil || transport.TLSClientConfig.InsecureSkipVerify {
		t.Fatal("production transport trust/proxy changed")
	}
	transport.TLSClientConfig = transport.TLSClientConfig.Clone()
	transport.TLSClientConfig.RootCAs = roots
	if mode == "TLS-trust" {
		transport.TLSClientConfig.RootCAs = x509.NewCertPool()
	}
	defer transport.CloseIdleConnections()
	rawDial := transport.DialContext
	detached := make(chan bool, 4)
	transport.DialContext = func(dial context.Context, network, target string) (net.Conn, error) {
		_, hasDeadline := dial.Deadline()
		detached <- !hasDeadline
		return rawDial(dial, network, target)
	}
	client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	query, err := ownedDNSQuery("example.com", dnsmessage.TypeA)
	if err != nil {
		t.Fatal(err)
	}
	perform := func() error {
		if mode == "missing-marker" {
			request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
			if err != nil {
				return err
			}
			response, err := client.Do(request)
			if response != nil {
				response.Body.Close()
			}
			return err
		}
		if kind == "DoH" {
			answer, err := ownedDoHExchange(ctx, client, query)
			if err == nil {
				_, err = parseOwnedDNSAnswer(query, answer)
			}
			return err
		}
		body, err := ownedHTTPSBody(ctx, client, url, "", 256, true)
		if err == nil && string(body) != "fixture body" {
			return errors.New("unexpected fixture HTTPS bytes")
		}
		return err
	}
	started := time.Now()
	finished := make(chan error, 1)
	go func() { finished <- perform() }()
	if mode == "greeting-cancel" || mode == "CONNECT-cancel" {
		select {
		case <-fixture.ready:
		case <-time.After(time.Second):
			t.Fatal("SOCKS phase not reached; request deadline may have been detached")
		}
		cancel()
	}
	var probeErr error
	select {
	case probeErr = <-finished:
	case <-time.After(4 * time.Second):
		t.Fatal("bounded owned HTTP operation did not return")
	}
	if (probeErr == nil) != (mode == "success") {
		t.Fatalf("mode %s unexpectedly returned %v", mode, probeErr)
	}
	if mode == "DNS-window" && (time.Since(started) < 2500*time.Millisecond || time.Since(started) > 3700*time.Millisecond) {
		t.Fatal("DoH did not use its actual three-second child window")
	}
	select {
	case stripped := <-detached:
		if !stripped {
			t.Fatal("real Transport did not exercise detached deadline context")
		}
	case <-time.After(time.Second):
		t.Fatal("actual Transport dial was not exercised")
	}
	if mode == "missing-marker" {
		if fixture.accepted.Load() != 0 || resolverCalls.Load() != 0 {
			t.Fatal("missing request marker opened SOCKS or resolved a name")
		}
		return
	}
	if mode == "greeting-cancel" || mode == "CONNECT-cancel" || mode == "greeting-deadline" || mode == "CONNECT-deadline" || mode == "DNS-window" {
		select {
		case peerErr := <-fixture.closed:
			if !errors.Is(peerErr, io.EOF) {
				t.Fatalf("canceled SOCKS connection was not closed: %v", peerErr)
			}
		case <-time.After(time.Second):
			t.Fatal("SOCKS peer remained open after cancellation/deadline")
		}
	}
	var result ownedDialFixtureResult
	select {
	case result = <-fixture.result:
	case <-time.After(time.Second):
		t.Fatal("SOCKS/TLS fixture did not finish")
	}
	wantConnects := int32(1)
	if mode == "greeting-cancel" || mode == "greeting-deadline" || mode == "DNS-window" {
		wantConnects = 0
	}
	if fixture.accepted.Load() != 1 || fixture.connects.Load() != wantConnects {
		t.Fatal("owned transport retried or fell back to a second connection")
	}
	if wantConnects == 1 && result.literal != netip.MustParseAddrPort("1.1.1.1:443") {
		t.Fatal("CONNECT destination was not the single checked public literal")
	}
	if mode == "success" && (result.err != nil || result.serverName != wantServerName) {
		t.Fatalf("original TLS hostname/HTTP exchange lost: %#v", result)
	}
	if kind == "DoH" && resolverCalls.Load() != 0 {
		t.Fatal("DoH bootstrap used a name resolver")
	}
}
