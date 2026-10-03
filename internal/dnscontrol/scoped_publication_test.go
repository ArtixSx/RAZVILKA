package dnscontrol

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

func TestScopedDNSServiceMatchNeverConvertsRefusalIntoMiss(t *testing.T) {
	r, key := scopedFixture(t)
	query := scopedQuery(t, "example.com", dnsmessage.TypeA)
	if matched, err := r.MatchClientQuery(context.Background(), key.client, query); !matched || err != nil {
		t.Fatal("exact service not selected", matched, err)
	}
	if matched, err := r.MatchClientQuery(context.Background(), key.client, scopedQuery(t, "unknown.example", dnsmessage.TypeAAAA)); matched || err != nil {
		t.Fatal("valid service miss", matched, err)
	}
	if matched, err := r.MatchClientQuery(context.Background(), key.client, []byte("bad")); matched || err == nil {
		t.Fatal("malformed query became a default miss", matched, err)
	}
	choice := r.choices[key]
	choice.provider.DoH = "https://changed.example/dns-query"
	r.choices[key] = choice
	if matched, err := r.MatchClientQuery(context.Background(), key.client, query); !matched || !errors.Is(err, ErrServiceDNSChanged) {
		t.Fatal("changed provider became a default miss", matched, err)
	}
	r.guard = func(context.Context) error { return ErrServiceDNSChanged }
	if matched, err := r.MatchClientQuery(context.Background(), key.client, scopedQuery(t, "unknown.example", dnsmessage.TypeA)); matched || !errors.Is(err, ErrServiceDNSChanged) {
		t.Fatal("revoked query became an authorized default miss", matched, err)
	}
}

func TestScopedDNSHandlerOwnsFinalUDPTCPPublication(t *testing.T) {
	for _, protocol := range []string{"udp", "tcp"} {
		for _, revoked := range []bool{false, true} {
			name := protocol + "/allowed"
			if revoked {
				name = protocol + "/revoked after resolve"
			}
			t.Run(name, func(t *testing.T) {
				udp, tcp := scopedSockets(t, "127.0.0.1:0")
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				var live atomic.Bool
				live.Store(true)
				published := make(chan struct{}, 1)
				var sent atomic.Int32
				handler := ScopedDNSHandler{
					Admit: func(context.Context, netip.Addr) error { return nil },
					Resolve: func(_ context.Context, _ netip.Addr, query []byte) ([]byte, error) {
						wire := scopedPack(t, scopedResponse(t, query))
						if revoked {
							live.Store(false)
						}
						return wire, nil
					},
					Publish: func(_ context.Context, _ netip.Addr, _ []byte, send func() error) error {
						defer func() { published <- struct{}{} }()
						if !live.Load() {
							return ErrScopedDNS
						}
						sent.Add(1)
						return send()
					},
				}
				done := make(chan error, 1)
				go func() { done <- ServeScopedDNS(ctx, udp, tcp, handler) }()
				address := udp.LocalAddr().String()
				if protocol == "tcp" {
					address = tcp.Addr().String()
				}
				conn, err := net.Dial(protocol, address)
				if err != nil {
					t.Fatal(err)
				}
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(500 * time.Millisecond))
				query := scopedQuery(t, "unknown.example", dnsmessage.TypeA)
				request := query
				if protocol == "tcp" {
					prefix := make([]byte, 2)
					binary.BigEndian.PutUint16(prefix, uint16(len(query)))
					request = append(prefix, query...)
				}
				if _, err := conn.Write(request); err != nil {
					t.Fatal(err)
				}
				select {
				case <-published:
				case <-time.After(time.Second):
					t.Fatal("final publication gate not called")
				}
				buffer := make([]byte, 4096)
				var n int
				if protocol == "tcp" {
					n, err = io.ReadFull(conn, buffer[:2])
				} else {
					n, err = conn.Read(buffer)
				}
				if revoked {
					if err == nil || n != 0 || sent.Load() != 0 {
						t.Fatal("revoked answer or TCP prefix was published", n, err, sent.Load())
					}
				} else {
					if err != nil || sent.Load() != 1 {
						t.Fatal("authorized publication", n, err, sent.Load())
					}
					if protocol == "tcp" {
						if n < 2 {
							t.Fatal("missing TCP prefix")
						}
						length := int(binary.BigEndian.Uint16(buffer[:2]))
						if n-2 < length {
							if _, err := io.ReadFull(conn, buffer[n:2+length]); err != nil {
								t.Fatal(err)
							}
						}
						buffer = buffer[2 : 2+length]
					} else {
						buffer = buffer[:n]
					}
					var reply dnsmessage.Message
					if reply.Unpack(buffer) != nil || reply.ID != binary.BigEndian.Uint16(query[:2]) || !reply.Response {
						t.Fatal("incorrect published DNS frame")
					}
				}
				cancel()
				select {
				case <-done:
				case <-time.After(time.Second):
					t.Fatal("publication worker not joined")
				}
			})
		}
	}
}

func TestScopedDNSPublicationCannotRetainOrReuseSend(t *testing.T) {
	var delayed func() error
	sent := 0
	handler := ScopedDNSHandler{Publish: func(_ context.Context, _ netip.Addr, _ []byte, send func() error) error {
		delayed = send
		return nil
	}}
	if err := publishScopedDNS(context.Background(), handler, netip.MustParseAddr("127.0.0.1"), nil, func() error { sent++; return nil }); err != nil {
		t.Fatal(err)
	}
	if delayed == nil || !errors.Is(delayed(), ErrScopedDNS) || sent != 0 {
		t.Fatal("send retained beyond owner publication lease")
	}
	handler.Publish = func(_ context.Context, _ netip.Addr, _ []byte, send func() error) error {
		if err := send(); err != nil {
			return err
		}
		return send()
	}
	if err := publishScopedDNS(context.Background(), handler, netip.MustParseAddr("127.0.0.1"), nil, func() error { sent++; return nil }); !errors.Is(err, ErrScopedDNS) || sent != 1 {
		t.Fatal("publication replayed", sent, err)
	}
}

func TestScopedDNSHandlerRequiresPublicationBeforeServing(t *testing.T) {
	udp, tcp := scopedSockets(t, "127.0.0.1:0")
	defer udp.Close()
	defer tcp.Close()
	called := false
	handler := ScopedDNSHandler{
		Admit: func(context.Context, netip.Addr) error { called = true; return nil },
		Resolve: func(context.Context, netip.Addr, []byte) ([]byte, error) {
			called = true
			return nil, nil
		},
	}
	if err := ServeScopedDNS(context.Background(), udp, tcp, handler); !errors.Is(err, ErrScopedDNS) || called {
		t.Fatal("incomplete owner was accepted", err, called)
	}
	// Rejection precedes socket ownership: a valid owner can still use them.
	if err := udp.SetReadDeadline(time.Now()); err != nil {
		t.Fatal("rejected handler closed UDP", err)
	}
	if err := tcp.SetDeadline(time.Now()); err != nil {
		t.Fatal("rejected handler closed TCP", err)
	}
}

func TestScopedDNSListenerPreservesExplicitLocalBaseline(t *testing.T) {
	r, _ := scopedFixture(t)
	var calls atomic.Int32
	r.baseline = func(_ context.Context, query []byte) ([]byte, error) {
		calls.Add(1)
		var request dnsmessage.Message
		if err := request.Unpack(query); err != nil {
			return nil, err
		}
		return scopedPack(t, dnsmessage.Message{
			Header:    dnsmessage.Header{ID: request.ID, Response: true, RecursionAvailable: true, RecursionDesired: true},
			Questions: request.Questions,
			Answers: []dnsmessage.Resource{{
				Header: dnsmessage.ResourceHeader{Name: request.Questions[0].Name, Type: dnsmessage.TypeTXT, Class: dnsmessage.ClassINET, TTL: 60},
				Body:   &dnsmessage.TXTResource{TXT: []string{"local policy"}},
			}},
		}), nil
	}
	udp, tcp := scopedSockets(t, "127.0.0.1:0")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- r.Serve(ctx, udp, tcp) }()
	conn, err := net.Dial("tcp", tcp.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	reply := scopedTCPReply(t, conn, scopedQuery(t, "router.home.arpa", dnsmessage.TypeTXT))
	if reply.RCode != dnsmessage.RCodeSuccess || len(reply.Answers) != 1 || calls.Load() != 1 {
		t.Fatal("explicit local baseline changed", reply, calls.Load())
	}
	// A selected service with an unsupported type must still be refused.
	reply = scopedTCPReply(t, conn, scopedQuery(t, "example.com", dnsmessage.TypeTXT))
	if reply.RCode != dnsmessage.RCodeRefused || calls.Load() != 1 {
		t.Fatal("selected service leaked to baseline", reply, calls.Load())
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("baseline worker not joined")
	}
}
