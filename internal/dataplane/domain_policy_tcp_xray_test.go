package dataplane

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/autonomy"
	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/dnscontrol"
)

// These are source/socket MODELS. NodeStore eligibility, Manager resource,
// physical MAC/iif, synthetic DNAT, transition and process identity are fixture
// seams, not native proof. The accepted TCP bytes and numeric SOCKS exchange
// are real local sockets. Root alone owns actual router/Xray/VLESS tests.
type syntheticTCPModelOwner struct {
	lease      *syntheticTCPModelLease
	processErr error
	admitted   atomic.Int32
	prepared   atomic.Int32
	lookup     *dnscontrol.SyntheticDNSMapping
}

func (o *syntheticTCPModelOwner) WithTCPProcess(ctx context.Context, _ ProcessSpec, _ string, consume func(context.Context) error) error {
	if o.processErr != nil {
		return o.processErr
	}
	return consume(ctx)
}

func (o *syntheticTCPModelOwner) CheckTCPProcess(ctx context.Context, _ ProcessSpec, _ string) error {
	return errors.Join(ctx.Err(), o.processErr)
}

func (o *syntheticTCPModelOwner) WithCapture(context.Context, DomainPolicyTCPCaptureSpec, *DomainPolicyTCPCapture, func(context.Context) error) error {
	return ErrDomainPolicyTCPConsumer // no native selector/transition in this model
}

func (o *syntheticTCPModelOwner) CheckCapture(ctx context.Context, _ *DomainPolicyTCPCapture) error {
	return ctx.Err()
}
func (o *syntheticTCPModelOwner) PrepareSyntheticCapture(context.Context, *DomainPolicyTCPCapture, *dnscontrol.SyntheticDNSMapping) error {
	o.prepared.Add(1)
	return ErrDomainPolicyTCPConsumer
}
func (o *syntheticTCPModelOwner) CurrentSyntheticCapture(context.Context, *DomainPolicyTCPCapture, *dnscontrol.SyntheticDNSMapping) error {
	return ErrDomainPolicyTCPConsumer
}
func (o *syntheticTCPModelOwner) LookupPublished(context.Context, netip.Addr, netip.Addr) (*dnscontrol.SyntheticDNSMapping, error) {
	if o.lookup != nil {
		return o.lookup, nil
	}
	return nil, ErrDomainPolicyTCPConsumer
}

func (o *syntheticTCPModelOwner) AdmitTCP(context.Context, DomainPolicyTCPSocket) (DomainPolicyTCPFlowLease, error) {
	o.admitted.Add(1)
	return o.lease, nil
}

type syntheticTCPModelLease struct {
	mapping  domainPolicyTCPSyntheticMapping
	policy   *DomainPolicy
	guard    func(int32) error
	calls    atomic.Int32
	leaseCtx context.Context
}

func (l *syntheticTCPModelLease) Binding() (*dnscontrol.SyntheticDNSMapping, string) {
	return nil, "model-flow-original-1" // this byte/backend fixture has no original DNS producer
}

func (l *syntheticTCPModelLease) Guard(ctx context.Context, _ DomainPolicyTCPSocket) (autonomy.ScopeObservation, error) {
	n := l.calls.Add(1)
	if l.guard != nil {
		if err := l.guard(n); err != nil {
			return autonomy.ScopeObservation{}, err
		}
	}
	return cloneDomainPolicyScope(l.policy.scope), ctx.Err()
}

func (l *syntheticTCPModelLease) WithFlow(ctx context.Context, _ DomainPolicyTCPSocket, forward func(context.Context) error) error {
	if l.leaseCtx != nil {
		ctx = l.leaseCtx
	}
	return forward(ctx)
}

func syntheticTCPModelFixture(t *testing.T) (*scopedXrayFixture, *DomainPolicy, DomainPolicyTCPCaptureSpec, *syntheticTCPModelOwner) {
	t.Helper()
	f := scopedXrayTestFixture(t)
	p, original, _ := domainPolicyFixture(t, nil)
	now := time.Now()
	p.scope.ObservedAt, p.scope.FreshUntil = now.Add(-time.Second), now.Add(time.Minute)
	p.services[0].ID = "telegram"
	p.services[0].Route = f.plan.Routes[0].Resolved
	s := DomainPolicyTCPCaptureSpec{Client: original.Client, DeviceID: "selected", Listen: netip.MustParseAddrPort("192.168.1.1:18091"), Limits: DomainPolicySniffLimits{Bytes: 16 << 10, Timeout: 100 * time.Millisecond},
		Xray: DomainPolicyTCPXraySpec{Generation: p.generation, NetworkProfile: executionNetwork, ServiceID: "telegram", NodeID: f.plan.Routes[0].Resolved[5:], Name: "service.example.com", RealIP: original.Destination}}
	m := domainPolicyTCPSyntheticMapping{Generation: p.generation, PublicationID: "model-possibly-issued-1", Name: s.Xray.Name, ServiceID: s.Xray.ServiceID, NodeID: s.Xray.NodeID, Client: original.Client,
		SyntheticIP: netip.MustParseAddr("198.18.0.17"), RealIP: s.Xray.RealIP, ExpiresAt: now.Add(time.Minute)}
	o := &syntheticTCPModelOwner{lease: &syntheticTCPModelLease{mapping: m, policy: p}}
	if !s.valid() {
		t.Fatal("invalid fixture intent")
	}
	return f, p, s, o
}

func syntheticTCPModelSocket(s DomainPolicyTCPCaptureSpec, m domainPolicyTCPSyntheticMapping, port uint16) DomainPolicyTCPSocket {
	return DomainPolicyTCPSocket{Source: netip.AddrPortFrom(s.Client.Address, 32123), OriginalDestination: netip.AddrPortFrom(m.SyntheticIP, port), Listener: s.Listen}
}

// Byte/backend MODEL only. It constructs a private test comparison seal and
// exercises HandleTCP + actual numeric SOCKS. It does NOT call the production
// capture handler, prepare an original DNS mapping or grant publication.
func syntheticTCPBytesBackendModel(p *DomainPolicy, ctx context.Context, conn *net.TCPConn, spec DomainPolicyTCPCaptureSpec, owner *syntheticTCPModelOwner, xray *DomainPolicyTCPXray, observe func(*net.TCPConn) (DomainPolicyTCPSocket, error)) (DomainPolicyDecision, error) {
	socket, err := observe(conn)
	if err != nil {
		_ = conn.Close()
		return DomainPolicyDecision{Kind: "refused"}, err
	}
	mapping := owner.lease.mapping
	b := &domainPolicyTCPSyntheticBinding{mapping: mapping, socket: socket, spec: spec.Xray}
	flow := DomainPolicyTCPFlow{Generation: mapping.Generation, FlowID: "bytes-backend-model-only", Source: socket.Source, Destination: socket.OriginalDestination, Client: mapping.Client, synthetic: b}
	runtime := DomainPolicyTCPRuntime{Limits: spec.Limits, Dial: xray.dial,
		Guard: func(c context.Context, _ DomainPolicyTCPFlow) (autonomy.ScopeObservation, error) {
			if !time.Now().Before(mapping.ExpiresAt) {
				return autonomy.ScopeObservation{}, ErrDomainPolicyTCPConsumer
			}
			return owner.lease.Guard(c, socket)
		},
		Lease: func(c context.Context, _ DomainPolicyTCPFlow, _ DomainPolicyDecision, forward func(context.Context) error) error {
			return owner.lease.WithFlow(c, socket, forward)
		},
	}
	return p.HandleTCP(ctx, conn, flow, runtime)
}

func syntheticTCPModelSOCKS(t *testing.T, f *scopedXrayFixture, target netip.AddrPort) (<-chan []byte, <-chan error, *atomic.Int32) {
	t.Helper()
	listener, err := net.ListenTCP("tcp4", net.TCPAddrFromAddrPort(netip.MustParseAddrPort("127.0.0.1:0")))
	if err != nil {
		t.Fatal(err)
	}
	f.a.SOCKSPort = int(listener.Addr().(*net.TCPAddr).AddrPort().Port())
	t.Cleanup(func() { _ = listener.Close() })
	payloads, done := make(chan []byte, 1), make(chan error, 1)
	calls := &atomic.Int32{}
	go func() {
		conn, err := listener.AcceptTCP()
		if err != nil {
			done <- err
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
		calls.Add(1)
		greeting := make([]byte, 3)
		if _, err = io.ReadFull(conn, greeting); err == nil && !bytes.Equal(greeting, []byte{5, 1, 0}) {
			err = errors.New("unexpected SOCKS greeting")
		}
		if err == nil {
			_, err = conn.Write([]byte{5, 0})
		}
		request := make([]byte, 10)
		if err == nil {
			_, err = io.ReadFull(conn, request)
		}
		ip := target.Addr().As4()
		if err == nil && (!bytes.Equal(request[:4], []byte{5, 1, 0, 1}) || !bytes.Equal(request[4:8], ip[:]) || binary.BigEndian.Uint16(request[8:]) != target.Port()) {
			err = errors.New("SOCKS did not receive the separate pinned IPv4 target")
		}
		if err == nil {
			_, err = conn.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 0})
		}
		var data []byte
		if err == nil {
			data, err = io.ReadAll(conn)
		}
		if err == nil {
			_, err = conn.Write([]byte("ok"))
			_ = conn.CloseWrite()
		}
		payloads <- data
		done <- err
	}()
	return payloads, done, calls
}

func TestDomainPolicySyntheticTCPModelActualHTTPAndTLSNumericSOCKS(t *testing.T) {
	for _, kind := range []string{"http", "tls"} {
		t.Run(kind, func(t *testing.T) {
			f, p, spec, owner := syntheticTCPModelFixture(t)
			port := uint16(80)
			payload := []byte("GET / HTTP/1.1\r\nHost: service.example.com\r\n\r\nbody")
			if kind == "tls" {
				port, payload = 443, domainPolicyHello(t, spec.Xray.Name)
			}
			socket := syntheticTCPModelSocket(spec, owner.lease.mapping, port)
			payloads, socksDone, calls := syntheticTCPModelSOCKS(t, f, netip.AddrPortFrom(spec.Xray.RealIP, port))
			err := f.a.WithDomainPolicyTCPXray(context.Background(), spec.Xray, owner, func(ctx context.Context, xray *DomainPolicyTCPXray) error {
				client, capture := domainPolicyTCPPair(t)
				done := make(chan error, 1)
				go func() {
					d, err := syntheticTCPBytesBackendModel(p, ctx, capture, spec, owner, xray, func(*net.TCPConn) (DomainPolicyTCPSocket, error) { return socket, nil })
					if d.Kind != "service" || d.Route != p.services[0].Route {
						t.Errorf("actual bytes did not select reviewed route: %+v", d)
					}
					done <- err
				}()
				_, _ = client.Write(payload[:7])
				_, _ = client.Write(payload[7:])
				_ = client.CloseWrite()
				reply, err := io.ReadAll(client)
				if err != nil || string(reply) != "ok" {
					t.Errorf("reply %q: %v", reply, err)
				}
				return <-done
			})
			if err != nil {
				t.Fatal(err)
			}
			if err := <-socksDone; err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(<-payloads, payload) || calls.Load() != 1 || f.processes.Running(f.a.engineProcess()) {
				t.Fatal("prefix changed, fallback or process not retired")
			}
		})
	}
}

func TestDomainPolicySyntheticTCPModelCaptureRefusals(t *testing.T) {
	for _, kind := range []string{"real destination", "wrong source", "wrong name", "literal Host", "ECH", "expired", "excluded MAC", "excluded resource", "unprepared transition", "generation revoked before dial"} {
		t.Run(kind, func(t *testing.T) {
			f, p, spec, owner := syntheticTCPModelFixture(t)
			socket := syntheticTCPModelSocket(spec, owner.lease.mapping, 80)
			payload := []byte("GET / HTTP/1.1\r\nHost: service.example.com\r\n\r\n")
			switch kind {
			case "real destination":
				socket.OriginalDestination = netip.AddrPortFrom(spec.Xray.RealIP, 80)
			case "wrong source":
				socket.Source = netip.MustParseAddrPort("192.168.1.99:32123")
			case "wrong name":
				payload = []byte("GET / HTTP/1.1\r\nHost: excluded.example.com\r\n\r\n")
			case "literal Host":
				payload = []byte("GET / HTTP/1.1\r\nHost: 93.184.215.14\r\n\r\n")
			case "ECH":
				payload = domainPolicyTLSExtension(t, domainPolicyHello(t, spec.Xray.Name), 0xfe0d, []byte{0})
			case "expired":
				owner.lease.mapping.ExpiresAt = time.Now().Add(-time.Second)
			case "excluded MAC":
				spec.Client.MAC = "02:00:00:00:00:01"
				owner.lease.mapping.Client = spec.Client
			case "excluded resource":
				p.policy.Rules = []config.NetworkRule{{ID: "negative", Revision: 1, Kind: "exact", Value: spec.Xray.Name, Action: "direct", Mandatory: true}}
			case "unprepared transition":
				owner.lease.guard = func(int32) error { return ErrDomainPolicyTCPConsumer }
			case "generation revoked before dial":
				owner.lease.guard = func(n int32) error {
					if n >= 3 {
						return ErrDomainPolicyTCPConsumer
					}
					return nil
				}
			}
			err := f.a.WithDomainPolicyTCPXray(context.Background(), spec.Xray, owner, func(ctx context.Context, xray *DomainPolicyTCPXray) error {
				client, capture := domainPolicyTCPPair(t)
				done := make(chan DomainPolicyDecision, 1)
				go func() {
					d, _ := syntheticTCPBytesBackendModel(p, ctx, capture, spec, owner, xray, func(*net.TCPConn) (DomainPolicyTCPSocket, error) { return socket, nil })
					done <- d
				}()
				_, _ = client.Write(payload)
				_ = client.CloseWrite()
				d := <-done
				if d.Kind == "service" || d.Kind == "baseline" || len(xray.connections) != 0 {
					t.Fatal("refusal opened outbound or baseline", d)
				}
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
			if (kind == "real destination" || kind == "wrong source") && owner.admitted.Load() != 0 {
				t.Fatal("real/unselected tuple reached admission")
			}
		})
	}
}

func TestDomainPolicySyntheticTCPModelMaterialMutationAndIdentityDrift(t *testing.T) {
	f, _, spec, owner := syntheticTCPModelFixture(t)
	original := f.a.NodeRoutes
	f.a.NodeRoutes = func(ctx context.Context, requests []NodeRouteRequest, profile string, now time.Time) (NodeRouteMaterial, error) {
		requests[0].Destinations = []string{"8.8.8.8/32"}
		return original(ctx, requests, profile, now)
	}
	if _, _, _, err := f.a.materializeDomainPolicyTCPXray(context.Background(), spec.Xray); err == nil {
		t.Fatal("materializer changed frozen request")
	}
	f.a.NodeRoutes = original
	err := f.a.WithDomainPolicyTCPXray(context.Background(), spec.Xray, owner, func(ctx context.Context, xray *DomainPolicyTCPXray) error {
		f.identity++
		if err := xray.check(ctx); err == nil {
			t.Fatal("replacement runtime accepted")
		}
		f.identity--
		f.endpoint = netip.MustParseAddr("8.8.4.4")
		if err := xray.check(ctx); !errors.Is(err, ErrNodeEndpointChanged) {
			t.Fatal("endpoint changed", err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestDomainPolicySyntheticTCPModelStopRetainsReplacementProcess(t *testing.T) {
	f, _, spec, owner := syntheticTCPModelFixture(t)
	err := f.a.WithDomainPolicyTCPXray(context.Background(), spec.Xray, owner, func(context.Context, *DomainPolicyTCPXray) error {
		f.identity++ // explicit process-identity model, not native PID replacement
		return nil
	})
	if !errors.Is(err, ErrDomainPolicyTCPConsumer) || !f.processes.Running(f.a.engineProcess()) {
		t.Fatal("replacement was stopped or cleanup pending disappeared", err)
	}
}

func TestDomainPolicySyntheticTCPModelRefusesRetainedProcessBeforeWriting(t *testing.T) {
	f, _, spec, owner := syntheticTCPModelFixture(t)
	process := f.a.engineProcess()
	if err := os.MkdirAll(process.Dir, 0o700); err != nil {
		t.Fatal(err)
	}
	previous := []byte("original retained config")
	if err := os.WriteFile(process.MatchArg, previous, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(process.PIDPath, []byte("foreign or unsettled PID"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := f.a.WithDomainPolicyTCPXray(context.Background(), spec.Xray, owner, func(context.Context, *DomainPolicyTCPXray) error { t.Fatal("adopted retained process"); return nil })
	if !errors.Is(err, ErrDomainPolicyTCPConsumer) || len(f.processes.startSpecs) != 0 {
		t.Fatal(err)
	}
	data, err := os.ReadFile(process.MatchArg)
	if err != nil || !bytes.Equal(data, previous) {
		t.Fatal("clobbered original config", err)
	}
}

func TestDomainPolicySyntheticTCPModelSpecialTargetsRefuseBeforeMaterialAndWrite(t *testing.T) {
	f, _, spec, owner := syntheticTCPModelFixture(t)
	if !spec.Client.Address.IsPrivate() || !spec.Listen.Addr().IsPrivate() || !spec.valid() {
		t.Fatal("public target filter affected LAN intent")
	}
	process := f.a.engineProcess()
	if err := os.MkdirAll(process.Dir, 0o700); err != nil {
		t.Fatal(err)
	}
	previous := []byte("untouched original config")
	if err := os.WriteFile(process.MatchArg, previous, 0o600); err != nil {
		t.Fatal(err)
	}
	f.a.NodeRoutes = func(context.Context, []NodeRouteRequest, string, time.Time) (NodeRouteMaterial, error) {
		t.Fatal("non-public target reached materializer")
		return NodeRouteMaterial{}, nil
	}
	p, flow, runtime := domainPolicyTCPFixture(t, nil)
	runtime.Dial = func(context.Context, DomainPolicyTCPFlow, DomainPolicyDecision) (net.Conn, error) {
		t.Fatal("non-public real target reached dial")
		return nil, nil
	}
	for _, value := range []string{"0.1.2.3", "192.0.0.8", "192.0.2.1", "198.51.100.1", "203.0.113.1", "240.0.0.1", "100.64.0.1", "198.18.0.1", "224.1.1.1", "127.0.0.1", "169.254.1.1", "10.1.1.1", "172.16.0.1", "192.168.1.1", "::ffff:93.184.215.14", "2001:db8::1"} {
		t.Run(value, func(t *testing.T) {
			ip := netip.MustParseAddr(value)
			bad := spec.Xray
			bad.RealIP = ip
			if err := f.a.WithDomainPolicyTCPXray(context.Background(), bad, owner, func(context.Context, *DomainPolicyTCPXray) error {
				t.Fatal("special target started runtime")
				return nil
			}); !errors.Is(err, ErrDomainPolicyTCPConsumer) {
				t.Fatal(err)
			}
			original := flow
			original.Destination = netip.AddrPortFrom(ip, 443)
			_, captured := domainPolicyTCPPair(t)
			if _, err := p.HandleTCP(context.Background(), captured, original, runtime); !errors.Is(err, ErrDomainPolicy) {
				t.Fatal("legacy public TCP admitted special target", err)
			}
		})
	}
	data, err := os.ReadFile(process.MatchArg)
	if err != nil || !bytes.Equal(data, previous) || len(f.processes.startSpecs) != 0 {
		t.Fatal("special target changed original runtime", err)
	}
}

func TestDomainPolicySyntheticTCPModelLeaseRevocationClosesAndJoins(t *testing.T) {
	f, p, spec, owner := syntheticTCPModelFixture(t)
	socket := syntheticTCPModelSocket(spec, owner.lease.mapping, 80)
	listener, err := net.ListenTCP("tcp4", net.TCPAddrFromAddrPort(netip.MustParseAddrPort("127.0.0.1:0")))
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	f.a.SOCKSPort = int(listener.Addr().(*net.TCPAddr).Port)
	prefixReceived := make(chan struct{})
	socksDone := make(chan error, 1)
	go func() {
		conn, err := listener.AcceptTCP()
		if err != nil {
			socksDone <- err
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
		greeting := make([]byte, 3)
		_, err = io.ReadFull(conn, greeting)
		if err == nil {
			_, err = conn.Write([]byte{5, 0})
		}
		request := make([]byte, 10)
		if err == nil {
			_, err = io.ReadFull(conn, request)
		}
		if err == nil {
			_, err = conn.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 0})
		}
		prefix := make([]byte, len("GET / HTTP/1.1\r\nHost: service.example.com\r\n\r\n"))
		if err == nil {
			_, err = io.ReadFull(conn, prefix)
		}
		close(prefixReceived)
		if err == nil {
			_, err = io.Copy(io.Discard, conn)
		}
		socksDone <- err
	}()
	err = f.a.WithDomainPolicyTCPXray(context.Background(), spec.Xray, owner, func(ctx context.Context, xray *DomainPolicyTCPXray) error {
		leaseCtx, revoke := context.WithCancel(ctx)
		defer revoke()
		owner.lease.leaseCtx = leaseCtx
		client, capture := domainPolicyTCPPair(t)
		done := make(chan error, 1)
		go func() {
			_, err := syntheticTCPBytesBackendModel(p, ctx, capture, spec, owner, xray, func(*net.TCPConn) (DomainPolicyTCPSocket, error) { return socket, nil })
			done <- err
		}()
		_, _ = client.Write([]byte("GET / HTTP/1.1\r\nHost: service.example.com\r\n\r\n"))
		<-prefixReceived
		revoke()
		select {
		case err := <-done:
			if !errors.Is(err, context.Canceled) {
				t.Fatal(err)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("revoked flow did not join")
		}
		xray.mu.Lock()
		active := len(xray.connections)
		xray.mu.Unlock()
		if active != 0 {
			t.Fatal("revoked lease retained outbound")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := <-socksDone; err != nil {
		t.Fatal(err)
	}
}

func TestDomainPolicySyntheticTCPScopeModelRejectsEscapedAndDoubleEntry(t *testing.T) {
	var saved func(context.Context) error
	calls := 0
	err := domainPolicyTCPSynchronousScope(context.Background(), func(consume func(context.Context) error) error { saved = consume; return nil }, func(context.Context) error { calls++; return nil })
	if !errors.Is(err, ErrDomainPolicyTCPConsumer) || !errors.Is(saved(context.Background()), ErrDomainPolicyTCPConsumer) || calls != 0 {
		t.Fatal("escaped callback executed")
	}
	err = domainPolicyTCPSynchronousScope(context.Background(), func(consume func(context.Context) error) error {
		return errors.Join(consume(context.Background()), consume(context.Background()))
	}, func(context.Context) error { calls++; return nil })
	if !errors.Is(err, ErrDomainPolicyTCPConsumer) || calls != 1 {
		t.Fatal("double entry executed", calls, err)
	}
	started := make(chan struct{})
	err = domainPolicyTCPSynchronousScope(context.Background(), func(consume func(context.Context) error) error {
		go func() { _ = consume(context.Background()) }()
		<-started
		return nil
	}, func(ctx context.Context) error { close(started); <-ctx.Done(); return ctx.Err() })
	if !errors.Is(err, ErrDomainPolicyTCPConsumer) || !errors.Is(err, context.Canceled) {
		t.Fatal("async callback was not revoked/joined", err)
	}
}

func TestDomainPolicySyntheticTCPModelMaterialAndMissingOriginalOwner(t *testing.T) {
	f, _, spec, owner := syntheticTCPModelFixture(t)
	resolver := f.a.Resolver
	f.a.Resolver = func(ctx context.Context, host string) ([]netip.Addr, error) {
		if host != "node.example" {
			t.Fatal("service name was re-resolved", host)
		}
		return resolver(ctx, host)
	}
	data, _, endpoint, err := f.a.materializeDomainPolicyTCPXray(context.Background(), spec.Xray)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(data)
	var doc map[string]any
	_ = json.Unmarshal(data, &doc)
	rule := doc["routing"].(map[string]any)["rules"].([]any)[0].(map[string]any)
	inbound := doc["inbounds"].([]any)[0].(map[string]any)
	if endpoint.IP != "1.1.1.1" || rule["network"] != "tcp" || rule["port"] != "80,443" || inbound["listen"] != "127.0.0.1" || inbound["settings"].(map[string]any)["udp"] != false {
		t.Fatal("wrong fixed TCP material")
	}
	owner.processErr = ErrDomainPolicyTCPConsumer
	if err := f.a.WithDomainPolicyTCPXray(context.Background(), spec.Xray, owner, func(context.Context, *DomainPolicyTCPXray) error {
		t.Fatal("missing original process owner consumed runtime")
		return nil
	}); !errors.Is(err, ErrDomainPolicyTCPConsumer) {
		t.Fatal(err)
	}
	if f.processes.Running(f.a.engineProcess()) {
		t.Fatal("missing owner started process")
	}
	if err := f.a.RunDomainPolicyTCP(context.Background(), nil, spec, owner); !errors.Is(err, ErrDomainPolicyTCPConsumer) {
		t.Fatal(err)
	}
}
