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

func TestNetworkPolicyDNSExistingListenerServiceDefaultAndRevocation(t *testing.T) {
	for _, transport := range []string{"udp", "tcp"} {
		for _, revoked := range []bool{false, true} {
			t.Run(transport+map[bool]string{false: "/normal", true: "/revoked"}[revoked], func(t *testing.T) {
				r, client := networkDNSFixture(t)
				r.now = time.Now
				r.service.cache.now = r.now
				var live atomic.Bool
				live.Store(true)
				var serviceCalls, defaultCalls, publishCalls atomic.Int32
				r.admit = func(_ context.Context, c netip.Addr, _ string) (NetworkPolicyDNSAdmission, error) {
					kind := "managed"
					if c != client || !live.Load() {
						kind = "outside"
					}
					return NetworkPolicyDNSAdmission{Authority: r.authority, Ingress: "br0", DeviceID: "selected", Kind: kind}, nil
				}
				scopedExchange(r.service, scopedDNSKey{client, "service.example.com"}, func(_ context.Context, q []byte) (dohResponse, error) {
					serviceCalls.Add(1)
					return dohResponse{wire: scopedPack(t, scopedResponse(t, q))}, nil
				})
				networkDefaultExchange(r, func(_ context.Context, q []byte) (dohResponse, error) {
					defaultCalls.Add(1)
					a := scopedResponse(t, q)
					var request dnsmessage.Message
					_ = request.Unpack(q)
					if request.Questions[0].Type == dnsmessage.TypeTXT {
						a.Answers = []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: request.Questions[0].Name, Type: dnsmessage.TypeTXT, Class: dnsmessage.ClassINET, TTL: 120}, Body: &dnsmessage.TXTResource{TXT: []string{"default"}}}}
					}
					return dohResponse{wire: scopedPack(t, a)}, nil
				})
				udp, tcp := scopedSockets(t, "127.0.0.1:0")
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				done := make(chan error, 1)
				owner := func(ctx context.Context, a NetworkPolicyDNSAdmission, send func() error) error {
					publishCalls.Add(1)
					if a.Authority != r.authority {
						return ErrNetworkPolicyDNS
					}
					if revoked {
						live.Store(false)
					}
					return send()
				}
				go func() { done <- r.Serve(ctx, udp, tcp, owner) }()
				conn, err := net.Dial(transport, udp.LocalAddr().String())
				if err != nil {
					t.Fatal(err)
				}
				defer conn.Close()
				queries := [][]byte{scopedQuery(t, "service.example.com", dnsmessage.TypeA), scopedQuery(t, "unknown.example.com", dnsmessage.TypeTXT)}
				for _, query := range queries {
					_ = conn.SetDeadline(time.Now().Add(400 * time.Millisecond))
					if transport == "tcp" {
						var size [2]byte
						binary.BigEndian.PutUint16(size[:], uint16(len(query)))
						_, err = conn.Write(append(size[:], query...))
					} else {
						_, err = conn.Write(query)
					}
					if err != nil {
						t.Fatal(err)
					}
					buffer := make([]byte, 4096)
					n := 0
					if transport == "tcp" {
						var size [2]byte
						_, err = io.ReadFull(conn, size[:])
						if err == nil {
							n = int(binary.BigEndian.Uint16(size[:]))
							_, err = io.ReadFull(conn, buffer[:n])
						}
					} else {
						n, err = conn.Read(buffer)
					}
					if revoked {
						if err == nil || n != 0 {
							t.Fatal("excluded afterResolve sent DNS bytes")
						}
						break
					}
					if err != nil {
						t.Fatal(err)
					}
					var answer dnsmessage.Message
					if answer.Unpack(buffer[:n]) != nil || !answer.Response || answer.RCode != dnsmessage.RCodeSuccess {
						t.Fatal(answer)
					}
				}
				if serviceCalls.Load() != 1 || !revoked && defaultCalls.Load() != 1 || revoked && defaultCalls.Load() != 0 {
					t.Fatal("duplicateResolve or fallback", serviceCalls.Load(), defaultCalls.Load())
				}
				if publishCalls.Load() == 0 {
					t.Fatal("owner publication bypassed")
				}
				cancel()
				select {
				case err := <-done:
					if !errors.Is(err, context.Canceled) {
						t.Fatal(err)
					}
				case <-time.After(2 * time.Second):
					t.Fatal("existinglistener workers didnotjoin")
				}
			})
		}
	}
}

func TestNetworkPolicyDNSPublishAccountsForFinalGuardAndKeepsObservationIdentity(t *testing.T) {
	r, client := networkDNSFixture(t)
	now := time.Date(2026, 10, 4, 0, 0, 0, 0, time.UTC)
	r.now = func() time.Time { return now }
	r.service.cache.now = r.now
	key := scopedDNSKey{client, "service.example.com"}
	scopedExchange(r.service, key, func(_ context.Context, q []byte) (dohResponse, error) {
		return dohResponse{wire: scopedPack(t, scopedResponse(t, q))}, nil
	})
	query := scopedQuery(t, key.host, dnsmessage.TypeA)
	if _, err := r.Resolve(context.Background(), client, query); err != nil {
		t.Fatal(err)
	}
	first, err := r.Observations(context.Background())
	if err != nil || len(first) != 1 {
		t.Fatal(first, err)
	}
	now = now.Add(121 * time.Second)
	stale, err := r.Observations(context.Background())
	if err != nil || len(stale) != 1 || first[0].ObservationID != stale[0].ObservationID {
		t.Fatal("diagnostic lifecycle changed observation identity", stale, err)
	}
	// Default answer loses all publication guard residence as well as DoH Age.
	networkDefaultExchange(r, func(_ context.Context, q []byte) (dohResponse, error) {
		return dohResponse{wire: scopedPack(t, scopedResponse(t, q))}, nil
	})
	checks := 0
	original := r.admit
	r.admit = func(ctx context.Context, c netip.Addr, n string) (NetworkPolicyDNSAdmission, error) {
		checks++
		if checks == 3 {
			now = now.Add(time.Second)
		}
		return original(ctx, c, n)
	}
	var ttl uint32
	if err := r.Publish(context.Background(), client, scopedQuery(t, "unknown.example.com", dnsmessage.TypeA), networkDNSModelPublisher, func(wire []byte) error {
		var answer dnsmessage.Message
		_ = answer.Unpack(wire)
		ttl = answer.Answers[0].Header.TTL
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if ttl != 119 {
		t.Fatal("finalguard increased wire lease", ttl, checks)
	}
}
