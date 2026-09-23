package dnscontrol

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

func scopedSockets(t *testing.T, address string) (*net.UDPConn, *net.TCPListener) {
	t.Helper()
	a, err := net.ResolveTCPAddr("tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	tcp, err := net.ListenTCP("tcp", a)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tcp.Close() })
	actual := tcp.Addr().(*net.TCPAddr)
	udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: actual.IP, Port: actual.Port})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = udp.Close() })
	return udp, tcp
}

func scopedTCPReply(t *testing.T, conn net.Conn, query []byte) dnsmessage.Message {
	t.Helper()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	var prefix [2]byte
	binary.BigEndian.PutUint16(prefix[:], uint16(len(query)))
	if _, err := conn.Write(append(prefix[:], query...)); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(conn, prefix[:]); err != nil {
		t.Fatal(err)
	}
	wire := make([]byte, int(binary.BigEndian.Uint16(prefix[:])))
	if _, err := io.ReadFull(conn, wire); err != nil {
		t.Fatal(err)
	}
	var message dnsmessage.Message
	if err := message.Unpack(wire); err != nil {
		t.Fatal(err)
	}
	return message
}

func TestScopedListenerUDPTruncationTCPFramingRefusalAndShutdown(t *testing.T) {
	r, key := scopedFixture(t)
	udp, tcp := scopedSockets(t, "127.0.0.1:0")
	var calls atomic.Int32
	scopedExchange(r, key, func(_ context.Context, q []byte) (dohResponse, error) {
		calls.Add(1)
		m := scopedResponse(t, q)
		m.Additionals = append(m.Additionals, dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName("example.com."), Type: 46, Class: dnsmessage.ClassINET, TTL: 60}, Body: &dnsmessage.UnknownResource{Type: 46, Data: make([]byte, 1400)}})
		return dohResponse{wire: scopedPack(t, m)}, nil
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- r.Serve(ctx, udp, tcp) }()
	u, err := net.Dial("udp", udp.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer u.Close()
	_ = u.SetDeadline(time.Now().Add(3 * time.Second))
	query := scopedQuery(t, "example.com", dnsmessage.TypeA)
	_, _ = u.Write(query)
	buffer := make([]byte, 4096)
	n, err := u.Read(buffer)
	if err != nil {
		t.Fatal(err)
	}
	var short dnsmessage.Message
	if err := short.Unpack(buffer[:n]); err != nil || !short.Truncated || len(short.Answers) != 0 || short.AuthenticData {
		t.Fatal("UDP did not return honest TC", err, short)
	}
	connection, err := net.Dial("tcp", tcp.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	full := scopedTCPReply(t, connection, query)
	if full.Truncated || len(full.Answers) != 1 || !full.AuthenticData {
		t.Fatal(full)
	}
	denied := scopedTCPReply(t, connection, scopedQuery(t, "other.example", dnsmessage.TypeA))
	if denied.RCode != dnsmessage.RCodeRefused || calls.Load() != 2 {
		t.Fatal("scope widened", denied, calls.Load())
	}
	// A partial frame stays idle; shutdown must join it without waiting for
	// its read deadline or leaving sockets held for the next owner.
	_, _ = connection.Write([]byte{0})
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("shutdown did not join workers")
	}
	address := tcp.Addr().String()
	nextUDP, nextTCP := scopedSockets(t, address)
	_ = nextUDP.Close()
	_ = nextTCP.Close()
}

func TestScopedListenerCancellationJoinsActiveDoH(t *testing.T) {
	r, key := scopedFixture(t)
	udp, tcp := scopedSockets(t, "127.0.0.1:0")
	entered := make(chan struct{})
	cleanup := make(chan struct{})
	scopedExchange(r, key, func(ctx context.Context, _ []byte) (dohResponse, error) {
		close(entered)
		<-ctx.Done()
		<-cleanup
		return dohResponse{}, ctx.Err()
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- r.Serve(ctx, udp, tcp) }()
	connection, err := net.Dial("udp", udp.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	_, _ = connection.Write(scopedQuery(t, "example.com", dnsmessage.TypeA))
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("no query")
	}
	cancel()
	select {
	case <-done:
		t.Fatal("returned before upstream joined")
	case <-time.After(30 * time.Millisecond):
	}
	close(cleanup)
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("cleanup did not finish")
	}
}

func TestScopedListenerBoundedWorkersAndUnauthorizedClient(t *testing.T) {
	r, key := scopedFixture(t)
	udp, tcp := scopedSockets(t, "127.0.0.1:0")
	entered := make(chan struct{}, 8)
	var active, maximum atomic.Int32
	scopedExchange(r, key, func(ctx context.Context, q []byte) (dohResponse, error) {
		n := active.Add(1)
		defer active.Add(-1)
		for {
			old := maximum.Load()
			if n <= old || maximum.CompareAndSwap(old, n) {
				break
			}
		}
		entered <- struct{}{}
		<-ctx.Done()
		return dohResponse{}, ctx.Err()
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- r.Serve(ctx, udp, tcp) }()
	connection, err := net.Dial("udp", udp.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	query := scopedQuery(t, "example.com", dnsmessage.TypeA)
	for i := 0; i < 4; i++ {
		_, _ = connection.Write(query)
		select {
		case <-entered:
		case <-time.After(2 * time.Second):
			t.Fatal("worker not started")
		}
	}
	_, _ = connection.Write(query)
	_ = connection.SetDeadline(time.Now().Add(2 * time.Second))
	wire := make([]byte, 4096)
	n, err := connection.Read(wire)
	if err != nil {
		t.Fatal(err)
	}
	var answer dnsmessage.Message
	_ = answer.Unpack(wire[:n])
	if answer.RCode != dnsmessage.RCodeServerFailure || maximum.Load() != 4 {
		t.Fatal("unbounded workers", answer, maximum.Load())
	}
	if r.hasClient(netip.MustParseAddr("127.0.0.2")) {
		t.Fatal("foreign source accepted")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("workers not stopped")
	}
}

// Hardware canary only: no firewall or system DNS writes. A matching client
// must send explicit queries to the reported high port during the 45s window.
func TestScopedDNSLiveClientCanary(t *testing.T) {
	if os.Getenv("RAZVILKA_TEST_SCOPED_DNS_LIVE") != "1" {
		t.Skip("requires explicit client DNS canary opt-in")
	}
	client, err := netip.ParseAddr(os.Getenv("RAZVILKA_TEST_DNS_CLIENT"))
	if err != nil {
		t.Fatal(err)
	}
	m, err := New("")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	r, err := m.NewScopedDNSResolver([]ClientDNSBinding{{client, os.Getenv("RAZVILKA_TEST_DNS_DOMAIN"), "private"}}, func(ctx context.Context) error { return ctx.Err() })
	if err != nil {
		t.Fatal(err)
	}
	udp, tcp := scopedSockets(t, os.Getenv("RAZVILKA_TEST_DNS_LISTEN"))
	t.Log("scoped DNS canary listening", tcp.Addr().String())
	if err := r.Serve(ctx, udp, tcp); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
	t.Log("scoped DNS canary sockets and workers closed")
}
