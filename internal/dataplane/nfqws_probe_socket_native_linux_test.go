//go:build linux

package dataplane

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// Real kernel descriptor/port tests only. These do not grant a managed source,
// register COMMON resources, install rules or send a packet to the destination.
func heldNFQWSProbeSocketFixture(t *testing.T, ctx context.Context) *nfqwsProbeBoundSocket {
	t.Helper()
	destination := netip.MustParseAddrPort("1.1.1.1:443")
	source, err := nfqwsProbeRouteSource(ctx, destination)
	if err != nil {
		t.Skip("no routable source available for descriptor-only fixture", err)
	}
	stop := errors.New("socket prepared; do not connect")
	var held *nfqwsProbeBoundSocket
	dialer := &net.Dialer{ControlContext: func(c context.Context, network, address string, raw syscall.RawConn) error {
		if network != "tcp4" || address != destination.String() {
			t.Fatal("unexpected socket scope", network, address)
		}
		var err error
		held, err = prepareNFQWSProbeBoundSocket(c, raw, source, destination)
		if err != nil {
			return err
		}
		return stop
	}}
	conn, err := dialer.DialContext(ctx, "tcp4", destination.String())
	if conn != nil {
		conn.Close()
		t.Fatal("descriptor fixture connected")
	}
	if !errors.Is(err, stop) || held == nil {
		t.Fatal("actual socket was not retained", err)
	}
	t.Cleanup(func() { _ = held.close() })
	return held
}

func probePortCanBeBound(t *testing.T, address netip.AddrPort) error {
	t.Helper()
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, unix.IPPROTO_TCP)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	return unix.Bind(fd, &unix.SockaddrInet4{Addr: address.Addr().As4(), Port: int(address.Port())})
}

func TestNFQWSProbeHeldDescriptorPreventsTupleReuseUntilCleanup(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	held := heldNFQWSProbeSocketFixture(t, ctx)
	if err := held.current(ctx); err != nil {
		t.Fatal("closing Go dial socket lost held owner", err)
	}
	if err := probePortCanBeBound(t, held.source); !errors.Is(err, unix.EADDRINUSE) {
		t.Fatal("foreign tuple reuse possible before cleanup", err)
	}
	copied := nfqwsProbeBoundSocket{self: held, fd: held.fd, stat: held.stat, source: held.source, destination: held.destination}
	if copied.current(ctx) == nil {
		t.Fatal("copied descriptor metadata became owner")
	}
	if err := held.close(); err != nil {
		t.Fatal(err)
	}
	if err := probePortCanBeBound(t, held.source); err != nil {
		t.Fatal("confirmed cleanup did not release port", err)
	}
	if held.current(ctx) == nil {
		t.Fatal("closed descriptor accepted")
	}
}

func TestNFQWSProbeCancellationDoesNotReleaseCleanupFailedTuple(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	held := heldNFQWSProbeSocketFixture(t, ctx)
	cancel()
	if held.current(ctx) == nil {
		t.Fatal("cancelled descriptor operation accepted")
	}
	// Model refusal to confirm rule cleanup by retaining the actual descriptor.
	// Cancellation and flow join alone must not make its port reusable.
	if err := probePortCanBeBound(t, held.source); !errors.Is(err, unix.EADDRINUSE) {
		t.Fatal("cancel freed cleanup-failed tuple", err)
	}
	if err := held.close(); err != nil {
		t.Fatal(err)
	}
	if err := probePortCanBeBound(t, held.source); err != nil {
		t.Fatal(err)
	}
}
