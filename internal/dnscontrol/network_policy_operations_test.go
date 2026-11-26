package dnscontrol

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/operationgate"
	"golang.org/x/net/dns/dnsmessage"
)

// The Gate and ephemeral loopback listener are real. Physical admission,
// provider exchanges remain explicit models. Store and durable-send owner are real.
func networkDNSOperationsFixture(t *testing.T) (*NetworkPolicyDNSResolver, netip.Addr, *operationgate.Gate, *operationgate.ControlEpochReview, string) {
	t.Helper()
	base, client := networkDNSFixture(t)
	gate := &operationgate.Gate{}
	root := filepath.Join(t.TempDir(), "control")
	if _, err := operationgate.InitializeSelfUpdateControl(context.Background(), root); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	held, release, err := gate.ExclusiveContext(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	control, err := gate.ReviewControlEpoch(held, root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = control.Close() })
	base.exclusions.identities = func(ctx context.Context, _ string) ([]string, error) {
		return nil, gate.WithExclusiveContext(ctx, func() error { return control.Current(ctx) })
	}
	plan, err := base.defaultDNS.manager.FreezeNetworkPolicyDNSPlan(held, base.authority.Generation, "private", []ClientDNSBinding{{Client: client, Domain: "service.example.com", ProfileID: "private"}}, base.exclusions)
	if err != nil {
		t.Fatal(err)
	}
	authority := base.authority
	authority.ControlEpoch = control.Reference().Sequence
	guard := func(ctx context.Context) error {
		deadline, bounded := ctx.Deadline()
		if !bounded || time.Until(deadline) > networkPolicyDNSOperationTimeout {
			return ErrNetworkPolicyDNS
		}
		return gate.WithExclusiveContext(ctx, func() error { return control.Current(ctx) })
	}
	r, err := base.defaultDNS.manager.NewNetworkPolicyDNSResolverForPlanWithOperations(held, plan, authority, gate, guard, func(ctx context.Context, c netip.Addr, _ string) (NetworkPolicyDNSAdmission, error) {
		if err := guard(ctx); err != nil {
			return NetworkPolicyDNSAdmission{}, err
		}
		if c != client {
			return NetworkPolicyDNSAdmission{}, ErrNetworkPolicyDNSOutside
		}
		return NetworkPolicyDNSAdmission{Authority: authority, Ingress: "br0", DeviceID: "selected", Kind: "managed"}, nil
	}, base.exclusions)
	if err != nil {
		t.Fatal(err)
	}
	r.now, r.service.cache.now = time.Now, time.Now
	return r, client, gate, control, root
}

func TestNetworkPolicyDNSOperationsFreshRequestLeaseThroughPublication(t *testing.T) {
	for _, transport := range []string{"udp", "tcp"} {
		t.Run(transport, func(t *testing.T) {
			r, client, gate, control, _ := networkDNSOperationsFixture(t)
			scopedExchange(r.service, scopedDNSKey{client, "service.example.com"}, func(ctx context.Context, q []byte) (dohResponse, error) {
				if err := r.guard(ctx); err != nil {
					return dohResponse{}, err
				}
				return dohResponse{wire: scopedPack(t, scopedResponse(t, q))}, nil
			})
			var mu sync.Mutex
			var operations []context.Context
			publisher := func(ctx context.Context, a NetworkPolicyDNSAdmission, observe func(func() error) error, write func() error) error {
				mu.Lock()
				operations = append(operations, ctx)
				mu.Unlock()
				if a.Authority != r.authority {
					return ErrNetworkPolicyDNS
				}
				return control.WithDNSReply(ctx, observe, write)
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
				// next request receives a fresh admission after this release.
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
	r, client, gate, control, _ := networkDNSOperationsFixture(t)
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
	go func() {
		done <- r.ServeWithOperations(ctx, udp, tcp, gate, func(ctx context.Context, _ NetworkPolicyDNSAdmission, observe func(func() error) error, write func() error) error {
			return control.WithDNSReply(ctx, observe, write)
		})
	}()
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
	if release, err := gate.Enter(context.Background()); err != nil {
		t.Fatal("upstream monopolized operation gate", err)
	} else {
		release()
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

func networkDNSOperationsWrite(t *testing.T, conn net.Conn, transport, name string) {
	t.Helper()
	query := scopedQuery(t, name, dnsmessage.TypeA)
	if transport == "tcp" {
		var size [2]byte
		binary.BigEndian.PutUint16(size[:], uint16(len(query)))
		query = append(size[:], query...)
	}
	if _, err := conn.Write(query); err != nil {
		t.Fatal(err)
	}
}

func networkDNSOperationsRead(conn net.Conn, transport string) ([]byte, error) {
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	wire := make([]byte, 4096)
	if transport == "tcp" {
		var size [2]byte
		if _, err := io.ReadFull(conn, size[:]); err != nil {
			return nil, err
		}
		n := int(binary.BigEndian.Uint16(size[:]))
		if n > len(wire) {
			return nil, ErrNetworkPolicyDNS
		}
		_, err := io.ReadFull(conn, wire[:n])
		return wire[:n], err
	}
	n, err := conn.Read(wire)
	return wire[:n], err
}

func TestNetworkPolicyDNSOperationsConcurrentQuestionsStopAndCloseJoin(t *testing.T) {
	for _, transport := range []string{"udp", "tcp"} {
		for _, end := range []string{"stop", "close"} {
			t.Run(transport+"/"+end, func(t *testing.T) {
				r, _, gate, control, root := networkDNSOperationsFixture(t)
				entered, joined := make(chan struct{}, 2), make(chan struct{}, 2)
				networkDefaultExchange(r, func(ctx context.Context, query []byte) (dohResponse, error) {
					var q dnsmessage.Message
					if q.Unpack(query) != nil {
						return dohResponse{}, errDNSAnswer
					}
					if q.Questions[0].Name.String() == "fast.example.org." {
						return dohResponse{wire: scopedPack(t, scopedResponse(t, query))}, nil
					}
					entered <- struct{}{}
					<-ctx.Done()
					joined <- struct{}{}
					return dohResponse{}, ctx.Err()
				})
				udp, tcp := scopedSockets(t, "127.0.0.1:0")
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				done := make(chan error, 1)
				go func() {
					done <- r.ServeWithOperations(ctx, udp, tcp, gate, func(ctx context.Context, _ NetworkPolicyDNSAdmission, observe func(func() error) error, write func() error) error {
						return control.WithDNSReply(ctx, observe, write)
					})
				}()
				connect := func() net.Conn {
					conn, err := net.Dial(transport, udp.LocalAddr().String())
					if err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() { _ = conn.Close() })
					return conn
				}
				wait := func(events <-chan struct{}, what string) {
					select {
					case <-events:
					case <-time.After(2 * time.Second):
						t.Fatal(what)
					}
				}
				// TCP accepts have their own short admission. Do not start two
				// unrelated accepts before asserting that this stalled provider
				// released its admission; those accepts can legitimately be busy.
				slow1 := connect()
				networkDNSOperationsWrite(t, slow1, transport, "slow-one.example.org")
				wait(entered, "first delayed provider not entered")
				readRelease, err := gate.Enter(context.Background())
				if err != nil {
					t.Fatal("upstream blocked ordinary shared read", err)
				}
				fast := connect()
				networkDNSOperationsWrite(t, fast, transport, "fast.example.org")
				readRelease()
				wire, err := networkDNSOperationsRead(fast, transport)
				var answer dnsmessage.Message
				if err != nil || answer.Unpack(wire) != nil || !answer.Response || answer.RCode != dnsmessage.RCodeSuccess {
					t.Fatal("second question blocked by first upstream", err)
				}
				slow2 := connect()
				networkDNSOperationsWrite(t, slow2, transport, "slow-two.example.org")
				wait(entered, "second delayed provider not entered")
				if end == "stop" {
					stopCtx, stopCancel := context.WithTimeout(context.Background(), time.Second)
					_, err := operationgate.RequestSelfUpdateStop(stopCtx, root, strings.Repeat("b", 32), 7)
					stopCancel()
					if err != nil {
						t.Fatal("upstream blocked durable Stop", err)
					}
				}
				// The existing session's Stop/close cancels its lifetime and joins
				// both provider workers; no DNS watcher/scheduler is introduced.
				cancel()
				wait(joined, "first provider did not cancel/join")
				wait(joined, "second provider did not cancel/join")
				select {
				case err := <-done:
					if !errors.Is(err, context.Canceled) {
						t.Fatal(err)
					}
				case <-time.After(2 * time.Second):
					t.Fatal("listener did not join concurrent questions")
				}
			})
		}
	}
}

func TestNetworkPolicyDNSOperationsDurableStopWinsAtFinalSocketLeaf(t *testing.T) {
	r, _, gate, control, root := networkDNSOperationsFixture(t)
	networkDefaultExchange(r, func(_ context.Context, query []byte) (dohResponse, error) {
		return dohResponse{wire: scopedPack(t, scopedResponse(t, query))}, nil
	})
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	writes := 0
	err := r.publishWithOperations(ctx, netip.MustParseAddr("127.0.0.1"), scopedQuery(t, "unknown.example.org", dnsmessage.TypeA), func(ctx context.Context, _ NetworkPolicyDNSAdmission, observe func(func() error) error, write func() error) error {
		if err := gate.WithExclusiveContext(ctx, func() error { return nil }); err != nil {
			t.Fatal(err)
		}
		if _, err := operationgate.RequestSelfUpdateStop(context.Background(), root, strings.Repeat("b", 32), 7); err != nil {
			t.Fatal(err)
		}
		return control.WithDNSReply(ctx, observe, write)
	}, func([]byte) error { writes++; return nil })
	if !errors.Is(err, operationgate.ErrSelfUpdateStopped) || writes != 0 {
		t.Fatal("prepared reply escaped durable Stop", writes, err)
	}
}

func TestNetworkPolicyDNSOperationsNegativeEditWinsAtFinalSocketLeaf(t *testing.T) {
	r, client, _, control, _ := networkDNSOperationsFixture(t)
	networkDefaultExchange(r, func(_ context.Context, query []byte) (dohResponse, error) {
		return dohResponse{wire: scopedPack(t, scopedResponse(t, query))}, nil
	})
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	writes := 0
	err := r.publishWithOperations(ctx, client, scopedQuery(t, "unknown.example.org", dnsmessage.TypeA), func(ctx context.Context, _ NetworkPolicyDNSAdmission, observe func(func() error) error, write func() error) error {
		manual := []config.ResourceMatch{{Kind: "exact", Value: "unknown.example.org"}}
		store := r.exclusions.store
		if _, err := store.UpdateResourceExclusions(context.Background(), store.Get(), &manual, nil); err != nil {
			t.Fatal(err)
		}
		return control.WithDNSReply(ctx, observe, write)
	}, func([]byte) error { writes++; return nil })
	if !errors.Is(err, config.ErrRevisionChanged) || writes != 0 || !r.exclusions.revoked.Load() {
		t.Fatal("prepared reply escaped original Store negative boundary", writes, err)
	}
}
