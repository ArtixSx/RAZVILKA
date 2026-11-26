package dataplane

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/autonomy"
	"github.com/ArtixSx/razvilka/internal/config"
)

func domainPolicyHello(t *testing.T, name string) []byte {
	t.Helper()
	client, server := net.Pipe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer client.Close()
		_ = tls.Client(client, &tls.Config{ServerName: name, MinVersion: tls.VersionTLS12}).Handshake()
	}()
	if err := server.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	header := make([]byte, 5)
	if _, err := io.ReadFull(server, header); err != nil {
		t.Fatal(err)
	}
	body := make([]byte, int(binary.BigEndian.Uint16(header[3:])))
	if _, err := io.ReadFull(server, body); err != nil {
		t.Fatal(err)
	}
	_ = server.Close()
	<-done
	return append(header, body...)
}

func domainPolicyTLSExtension(t *testing.T, hello []byte, kind uint16, value []byte) []byte {
	t.Helper()
	hello = slices.Clone(hello)
	// TLS record + handshake header + version/random + session/ciphers/compression.
	pos := 9 + 34
	pos += 1 + int(hello[pos])
	pos += 2 + int(binary.BigEndian.Uint16(hello[pos:]))
	pos += 1 + int(hello[pos])
	extension := []byte{byte(kind >> 8), byte(kind), byte(len(value) >> 8), byte(len(value))}
	extension = append(extension, value...)
	binary.BigEndian.PutUint16(hello[pos:], binary.BigEndian.Uint16(hello[pos:])+uint16(len(extension)))
	hello = append(hello, extension...)
	binary.BigEndian.PutUint16(hello[3:], uint16(len(hello)-5))
	size := len(hello) - 9
	hello[6], hello[7], hello[8] = byte(size>>16), byte(size>>8), byte(size)
	return hello
}

func TestDomainPolicyNameActualTLSFragmentedAndECH(t *testing.T) {
	hello := domainPolicyHello(t, "service.example.com")
	if e, done := parseDomainPolicyName(hello); !done || e.State != DomainPolicyNameVisible || e.Name != "service.example.com" || e.Source != "tls-sni" {
		t.Fatal(e, done)
	}
	body := hello[5:]
	var fragmented []byte
	for _, part := range [][]byte{body[:2], body[2:19], body[19:]} {
		fragmented = append(fragmented, 22, 3, 3, byte(len(part)>>8), byte(len(part)))
		fragmented = append(fragmented, part...)
	}
	for _, data := range [][]byte{hello, fragmented} {
		for i := 0; i < len(data); i++ {
			if e, done := parseDomainPolicyName(data[:i]); done {
				t.Fatal("partial ClientHello became authority", i, e)
			}
		}
		if e, done := parseDomainPolicyName(data); !done || e.State != DomainPolicyNameVisible || e.Name != "service.example.com" {
			t.Fatal("fragmented TLS lost actual name", e)
		}
	}
	for _, kind := range []uint16{0xfe0d, 0xffce} {
		data := domainPolicyTLSExtension(t, hello, kind, []byte{0, 0, 1, 0})
		if e, done := parseDomainPolicyName(data); !done || e.State != DomainPolicyNameEncrypted || e.Name != "" {
			t.Fatal("outer name became inner identity", kind, e)
		}
	}
	// Duplicate extension is ambiguous even when the injected value is benign.
	duplicate := domainPolicyTLSExtension(t, hello, 0, []byte{0, 0})
	if e, _ := parseDomainPolicyName(duplicate); e.State != DomainPolicyNameAmbiguous || e.Name != "" {
		t.Fatal(e)
	}
}

func TestDomainPolicyNameHTTPIdentityAndLiteral(t *testing.T) {
	for _, tc := range []struct {
		request string
		state   DomainPolicyNameState
		name    string
	}{
		{"GET / HTTP/1.1\r\nHost: service.example.com\r\n\r\nbody", DomainPolicyNameVisible, "service.example.com"},
		{"GET / HTTP/1.1\r\nHost: 93.184.215.14:80\r\n\r\n", DomainPolicyNameAbsent, ""},
		{"GET / HTTP/1.1\r\nHost: service.example.com\r\nHost: other.example.com\r\n\r\n", DomainPolicyNameAmbiguous, ""},
		{"GET http://other.example.com/ HTTP/1.1\r\nHost: service.example.com\r\n\r\n", DomainPolicyNameAmbiguous, ""},
		{"CONNECT service.example.com:443 HTTP/1.1\r\nHost: other.example.com\r\n\r\n", DomainPolicyNameAmbiguous, ""},
		{"GET / HTTP/1.1\r\nHost: service.example.com\r\n folded: host\r\n\r\n", DomainPolicyNameAmbiguous, ""},
		{"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", DomainPolicyNameOpaque, ""},
	} {
		e, done := parseDomainPolicyName([]byte(tc.request))
		if !done || e.State != tc.state || e.Name != tc.name {
			t.Fatal(tc.request, e, done)
		}
	}
}

func domainPolicyTCPFixture(t *testing.T, rules []config.NetworkRule) (*DomainPolicy, DomainPolicyTCPFlow, DomainPolicyTCPRuntime) {
	t.Helper()
	p, f, now := domainPolicyFixture(t, rules)
	flow := DomainPolicyTCPFlow{Generation: p.generation, FlowID: "owned-flow-1", Source: netip.AddrPortFrom(f.Client.Address, 32123), Destination: netip.AddrPortFrom(f.Destination, 443), Client: f.Client, DefaultCoverage: "supported"}
	runtime := DomainPolicyTCPRuntime{Limits: DomainPolicySniffLimits{Bytes: 16 << 10, Timeout: 100 * time.Millisecond}, Now: func() time.Time { return now }, Guard: func(context.Context, DomainPolicyTCPFlow) (autonomy.ScopeObservation, error) {
		return cloneDomainPolicyScope(p.scope), nil
	}, Lease: func(ctx context.Context, _ DomainPolicyTCPFlow, _ DomainPolicyDecision, forward func(context.Context) error) error {
		return forward(ctx)
	}}
	return p, flow, runtime
}

func domainPolicyTCPPair(t *testing.T) (*net.TCPConn, *net.TCPConn) {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	client, err := net.Dial("tcp4", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	server, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close(); _ = server.Close() })
	_ = client.SetDeadline(time.Now().Add(3 * time.Second))
	_ = server.SetDeadline(time.Now().Add(3 * time.Second))
	return client.(*net.TCPConn), server.(*net.TCPConn)
}

func TestDomainPolicyTCPActualBytesChooseBeforeOutbound(t *testing.T) {
	for _, tc := range []struct{ name, route, kind string }{
		{"service.example.com", "xray", "service"},
		{"unknown.example.com", "direct", "baseline"},
		{"93.184.215.14", "direct", "baseline"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, flow, runtime := domainPolicyTCPFixture(t, nil)
			client, captured := domainPolicyTCPPair(t)
			payload := []byte("GET /path HTTP/1.1\r\nHost: " + tc.name + "\r\n\r\nbody-unchanged")
			var received []byte
			var serverErr error
			serverDone := make(chan struct{})
			calls := 0
			runtime.Dial = func(_ context.Context, actual DomainPolicyTCPFlow, d DomainPolicyDecision) (net.Conn, error) {
				calls++
				if actual.Destination != flow.Destination || actual.Source != flow.Source || d.Route != tc.route || d.Kind != tc.kind {
					t.Errorf("wrong original tuple/outbound: %v %v", actual, d)
				}
				upstream, server := domainPolicyTCPPair(t)
				go func() {
					defer close(serverDone)
					received, serverErr = io.ReadAll(server)
					if serverErr == nil {
						_, serverErr = server.Write([]byte("reply"))
						_ = server.CloseWrite()
					}
				}()
				return upstream, nil
			}
			if tc.kind == "baseline" {
				runtime.BaselineDial = runtime.Dial // explicit protocol double for the baseline owner
				runtime.Dial = func(context.Context, DomainPolicyTCPFlow, DomainPolicyDecision) (net.Conn, error) {
					t.Error("unmatched flow reached bypass dial")
					return nil, ErrDomainPolicy
				}
			}
			done := make(chan error, 1)
			go func() {
				d, err := p.HandleTCP(context.Background(), captured, flow, runtime)
				if err == nil && (d.Kind != tc.kind || d.Route != tc.route) {
					err = ErrDomainPolicy
				}
				done <- err
			}()
			if _, err := client.Write(payload); err != nil {
				t.Fatal(err)
			}
			_ = client.CloseWrite()
			reply, err := io.ReadAll(client)
			if err != nil || string(reply) != "reply" {
				t.Fatal(string(reply), err)
			}
			if err := <-done; err != nil {
				t.Fatal(err)
			}
			<-serverDone
			if calls != 1 || serverErr != nil || !bytes.Equal(received, payload) {
				t.Fatal("bytes changed or fallback", calls, serverErr, received)
			}
		})
	}
}

func TestDomainPolicyTCPActualTLSSelectsRouteAndReplaysHello(t *testing.T) {
	p, flow, runtime := domainPolicyTCPFixture(t, nil)
	hello := domainPolicyHello(t, "service.example.com")
	client, captured := domainPolicyTCPPair(t)
	upstream, server := domainPolicyTCPPair(t)
	runtime.Dial = func(_ context.Context, original DomainPolicyTCPFlow, d DomainPolicyDecision) (net.Conn, error) {
		if d.Kind != "service" || d.Route != "xray" || original.Destination != flow.Destination {
			t.Errorf("TLS did not select from original flow: %v %v", original, d)
		}
		return upstream, nil
	}
	received := make(chan []byte, 1)
	go func() {
		data, _ := io.ReadAll(server)
		_, _ = server.Write([]byte("ok"))
		_ = server.CloseWrite()
		received <- data
	}()
	done := make(chan error, 1)
	go func() { _, err := p.HandleTCP(context.Background(), captured, flow, runtime); done <- err }()
	_, _ = client.Write(hello[:7])
	_, _ = client.Write(hello[7:])
	_ = client.CloseWrite()
	if reply, err := io.ReadAll(client); err != nil || string(reply) != "ok" {
		t.Fatal(string(reply), err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if data := <-received; !bytes.Equal(data, hello) {
		t.Fatal("sniff changed TLS bytes")
	}
}

func TestDomainPolicyTCPNameGuardAndNegativeGateNoDial(t *testing.T) {
	hello := domainPolicyHello(t, "service.example.com")
	for _, tc := range []struct {
		name      string
		payload   []byte
		excluded  bool
		bound     int
		coalesced bool
	}{
		{name: "ECH", payload: domainPolicyTLSExtension(t, hello, 0xfe0d, []byte{0})},
		{name: "ambiguous", payload: []byte("GET / HTTP/1.1\r\nHost: service.example.com\r\nHost: other.example.com\r\n\r\n")},
		{name: "opaque", payload: []byte{1, 2, 3}},
		{name: "timeout"},
		{name: "bound", payload: append([]byte("GET / HTTP/1.1\r\nX: "), bytes.Repeat([]byte("x"), 600)...), bound: 512},
		{name: "excluded before read", excluded: true},
		{name: "coalesced", payload: hello, coalesced: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, flow, runtime := domainPolicyTCPFixture(t, []config.NetworkRule{{ID: "mandatory", Revision: 1, Kind: "exact", Value: "service.example.com", Action: "direct", Mandatory: true}})
			if tc.excluded {
				flow.Client.MAC = "02:00:00:00:00:01"
			}
			flow.Coalesced = tc.coalesced
			if tc.bound != 0 {
				runtime.Limits.Bytes = tc.bound
			}
			var calls atomic.Int32
			runtime.Dial = func(context.Context, DomainPolicyTCPFlow, DomainPolicyDecision) (net.Conn, error) {
				calls.Add(1)
				return nil, errors.New("must not dial")
			}
			client, captured := domainPolicyTCPPair(t)
			done := make(chan DomainPolicyDecision, 1)
			go func() { d, _ := p.HandleTCP(context.Background(), captured, flow, runtime); done <- d }()
			if len(tc.payload) > 0 {
				_, _ = client.Write(tc.payload)
			}
			d := <-done
			if calls.Load() != 0 || tc.excluded && d.Kind != "outside" || !tc.excluded && d.Kind != "refused" {
				t.Fatal(d, calls.Load())
			}
		})
	}
}

func TestDomainPolicyTCPRevokedAfterSniffAndDialFailureNoFallback(t *testing.T) {
	for _, revoke := range []bool{true, false} {
		p, flow, runtime := domainPolicyTCPFixture(t, nil)
		var guards, calls atomic.Int32
		runtime.Guard = func(context.Context, DomainPolicyTCPFlow) (autonomy.ScopeObservation, error) {
			if guards.Add(1) >= 3 && revoke {
				return autonomy.ScopeObservation{}, ErrReviewChanged
			}
			return cloneDomainPolicyScope(p.scope), nil
		}
		runtime.Dial = func(context.Context, DomainPolicyTCPFlow, DomainPolicyDecision) (net.Conn, error) {
			calls.Add(1)
			return nil, errors.New("chosen backend failed")
		}
		client, captured := domainPolicyTCPPair(t)
		done := make(chan error, 1)
		go func() { _, err := p.HandleTCP(context.Background(), captured, flow, runtime); done <- err }()
		_, _ = client.Write([]byte("GET / HTTP/1.1\r\nHost: service.example.com\r\n\r\n"))
		if err := <-done; err == nil || revoke && calls.Load() != 0 || !revoke && calls.Load() != 1 {
			t.Fatal(err, calls.Load())
		}
	}
}

func TestDomainPolicyTCPRevokedAtFirstWriteSendsNoBytes(t *testing.T) {
	p, flow, runtime := domainPolicyTCPFixture(t, nil)
	var guards atomic.Int32
	runtime.Guard = func(context.Context, DomainPolicyTCPFlow) (autonomy.ScopeObservation, error) {
		if guards.Add(1) >= 4 {
			return autonomy.ScopeObservation{}, ErrReviewChanged
		}
		return cloneDomainPolicyScope(p.scope), nil
	}
	upstream, server := domainPolicyTCPPair(t)
	runtime.Dial = func(context.Context, DomainPolicyTCPFlow, DomainPolicyDecision) (net.Conn, error) {
		return upstream, nil
	}
	client, captured := domainPolicyTCPPair(t)
	done := make(chan error, 1)
	go func() { _, err := p.HandleTCP(context.Background(), captured, flow, runtime); done <- err }()
	_, _ = client.Write([]byte("GET / HTTP/1.1\r\nHost: service.example.com\r\n\r\nsecret"))
	if err := <-done; !errors.Is(err, ErrReviewChanged) {
		t.Fatal(err)
	}
	if data, err := io.ReadAll(server); len(data) != 0 || err != nil {
		t.Fatal("revoked flow sent bytes", data, err)
	}
}

func TestDomainPolicyTCPBaselineGrantRequiredAndExplicitSuffix(t *testing.T) {
	p, flow, runtime := domainPolicyTCPFixture(t, []config.NetworkRule{{ID: "direct", Revision: 1, Kind: "exact", Value: "service.example.com", Action: "direct", Mandatory: true}})
	var calls atomic.Int32
	runtime.Dial = func(context.Context, DomainPolicyTCPFlow, DomainPolicyDecision) (net.Conn, error) {
		calls.Add(1)
		return nil, nil
	}
	client, captured := domainPolicyTCPPair(t)
	done := make(chan DomainPolicyDecision, 1)
	go func() { d, _ := p.HandleTCP(context.Background(), captured, flow, runtime); done <- d }()
	_, _ = client.Write([]byte("GET / HTTP/1.1\r\nHost: service.example.com\r\n\r\n"))
	if d := <-done; d.Kind != "refused" || d.Reason != "BASELINE_FLOW_GRANT_REQUIRED" || calls.Load() != 0 {
		t.Fatal(d)
	}
	p, f, now := domainPolicyFixture(t, nil)
	f.Name = "child.service.example.com"
	if d := p.Decide(f, now); d.Kind != "baseline" {
		t.Fatal("exact service widened", d)
	}
	p.services[0].DomainSuffixes = []string{"service.example.com"}
	if d := p.Decide(f, now); d.Kind != "service" {
		t.Fatal("explicit suffix missed", d)
	}
}

func TestDomainPolicyTCPStopClosesAndJoinsForwarding(t *testing.T) {
	p, flow, runtime := domainPolicyTCPFixture(t, nil)
	client, captured := domainPolicyTCPPair(t)
	upstream, server := domainPolicyTCPPair(t)
	dialed := make(chan struct{})
	runtime.Dial = func(context.Context, DomainPolicyTCPFlow, DomainPolicyDecision) (net.Conn, error) {
		close(dialed)
		return upstream, nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := p.HandleTCP(ctx, captured, flow, runtime); done <- err }()
	_, _ = client.Write([]byte("GET / HTTP/1.1\r\nHost: service.example.com\r\n\r\n"))
	<-dialed
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Stop left owned readers unjoined")
	}
	_ = server.SetReadDeadline(time.Now().Add(time.Second))
	_, err := io.ReadAll(server)
	if e, ok := err.(net.Error); ok && e.Timeout() {
		t.Fatal("owned upstream stayed alive after joined Stop")
	}
}

func TestDomainPolicyTCPRejectsLateLeaseCallback(t *testing.T) {
	p, flow, runtime := domainPolicyTCPFixture(t, nil)
	var late func(context.Context) error
	var mu sync.Mutex
	runtime.Lease = func(_ context.Context, _ DomainPolicyTCPFlow, _ DomainPolicyDecision, forward func(context.Context) error) error {
		mu.Lock()
		late = forward
		mu.Unlock()
		return nil
	}
	var calls atomic.Int32
	runtime.Dial = func(context.Context, DomainPolicyTCPFlow, DomainPolicyDecision) (net.Conn, error) {
		calls.Add(1)
		return nil, nil
	}
	client, captured := domainPolicyTCPPair(t)
	done := make(chan error, 1)
	go func() { _, err := p.HandleTCP(context.Background(), captured, flow, runtime); done <- err }()
	_, _ = client.Write([]byte("GET / HTTP/1.1\r\nHost: service.example.com\r\n\r\n"))
	if err := <-done; err == nil {
		t.Fatal("missing synchronous lease accepted")
	}
	mu.Lock()
	callback := late
	mu.Unlock()
	if callback == nil || callback(context.Background()) == nil || calls.Load() != 0 {
		t.Fatal("late revoked callback dialed", calls.Load())
	}
}
