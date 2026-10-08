package dnscontrol

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/operationgate"
	"golang.org/x/net/dns/dnsmessage"
)

// The Gate and ephemeral loopback listener are real. Physical admission,
// provider exchanges and the durable-send owner are explicit protocol models.
func TestNetworkPolicyDNSOperationsFreshRequestLeaseThroughPublication(t *testing.T) {
	for _, transport := range []string{"udp", "tcp"} {
		t.Run(transport, func(t *testing.T) {
			r, client := networkDNSFixture(t)
			r.now, r.service.cache.now = time.Now, time.Now
			gate := &operationgate.Gate{}
			r.guard = func(ctx context.Context) error {
				deadline, bounded := ctx.Deadline()
				if !bounded || time.Until(deadline) > networkPolicyDNSOperationTimeout {
					return ErrNetworkPolicyDNS
				}
				return gate.WithExclusiveContext(ctx, func() error { return nil })
			}
			scopedExchange(r.service, scopedDNSKey{client, "service.example.com"}, func(ctx context.Context, q []byte) (dohResponse, error) {
				if err := r.guard(ctx); err != nil {
					return dohResponse{}, err
				}
				return dohResponse{wire: scopedPack(t, scopedResponse(t, q))}, nil
			})
			var mu sync.Mutex
			var operations []context.Context
			publisher := func(ctx context.Context, a NetworkPolicyDNSAdmission, send func() error) error {
				mu.Lock()
				operations = append(operations, ctx)
				mu.Unlock()
				if a.Authority != r.authority {
					return ErrNetworkPolicyDNS
				}
				return gate.WithExclusiveContext(ctx, send)
			}
			udp, tcp := scopedSockets(t, "127.0.0.1:0")
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan error, 1)
			go func() { done <- r.ServeWithOperations(ctx, udp, tcp, gate, publisher) }()
			conn, err := net.Dial(transport, udp.LocalAddr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			for i := 0; i < 2; i++ {
				query := scopedQuery(t, "service.example.com", dnsmessage.TypeA)
				_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
				var frame [2]byte
				if transport == "tcp" {
					binary.BigEndian.PutUint16(frame[:], uint16(len(query)))
					_, err = conn.Write(append(frame[:], query...))
				} else {
					_, err = conn.Write(query)
				}
				if err != nil {
					t.Fatal(err)
				}
				wire := make([]byte, 4096)
				var n int
				if transport == "tcp" {
					if _, err = io.ReadFull(conn, frame[:]); err != nil {
						t.Fatal(err)
					}
					n = int(binary.BigEndian.Uint16(frame[:]))
					_, err = io.ReadFull(conn, wire[:n])
				} else {
					n, err = conn.Read(wire)
				}
				var answer dnsmessage.Message
				if err != nil || answer.Unpack(wire[:n]) != nil || !answer.Response || answer.RCode != dnsmessage.RCodeSuccess {
					t.Fatal("finite original request did not publish", err, answer)
				}
				// Receipt of bytes precedes the final bookend and release. A
				// simultaneous request must refuse busy instead of borrowing it.
				until := time.Now().Add(time.Second)
				for {
					if _, idle := gate.IdleGeneration(); idle {
						break
					}
					if time.Now().After(until) {
						t.Fatal("completed query retained original operation")
					}
					runtime.Gosched()
				}
			}
			cancel()
			select {
			case err := <-done:
				if !errors.Is(err, context.Canceled) {
					t.Fatal(err)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("existing listener did not join requests")
			}
			mu.Lock()
			defer mu.Unlock()
			if len(operations) != 2 || operations[0] == operations[1] {
				t.Fatal("TCP/UDP requests reused operation", len(operations))
			}
			for _, old := range operations {
				if err := gate.WithExclusiveContext(old, func() error { return nil }); err == nil {
					t.Fatal("published query retained usable operation")
				}
			}
			if release, err := gate.Enter(context.Background()); err != nil {
				t.Fatal("request operation leaked", err)
			} else {
				release()
			}
		})
	}
}

func TestNetworkPolicyDNSOperationsCancellationJoinsProviderBeforeRelease(t *testing.T) {
	r, client := networkDNSFixture(t)
	gate := &operationgate.Gate{}
	r.guard = func(ctx context.Context) error { return gate.WithExclusiveContext(ctx, func() error { return nil }) }
	entered := make(chan struct{})
	joined := make(chan struct{})
	scopedExchange(r.service, scopedDNSKey{client, "service.example.com"}, func(ctx context.Context, _ []byte) (dohResponse, error) {
		close(entered)
		<-ctx.Done()
		close(joined)
		return dohResponse{}, ctx.Err()
	})
	udp, tcp := scopedSockets(t, "127.0.0.1:0")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- r.ServeWithOperations(ctx, udp, tcp, gate, networkDNSModelPublisher) }()
	conn, err := net.Dial("udp", udp.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Write(scopedQuery(t, "service.example.com", dnsmessage.TypeA)); err != nil {
		t.Fatal(err)
	}
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("request did not reach provider model")
	}
	if release, err := gate.Enter(context.Background()); !errors.Is(err, operationgate.ErrBusy) {
		if release != nil {
			release()
		}
		t.Fatal("operation released before provider joined", err)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("cancelled request not joined")
	}
	select {
	case <-joined:
	default:
		t.Fatal("operation outlived provider join")
	}
	if release, err := gate.Enter(context.Background()); err != nil {
		t.Fatal("cancelled request operation leaked", err)
	} else {
		release()
	}
}
