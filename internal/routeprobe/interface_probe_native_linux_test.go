//go:build linux

package routeprobe

import (
	"context"
	"errors"
	"net"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestInterfaceProbeLinuxSocketBindingReadback(t *testing.T) {
	// Old Linux kernels require CAP_NET_RAW even for the loopback device.
	// Distinguish this environment limitation from a failure in our binder.
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	bindErr := unix.SetsockoptString(fd, unix.SOL_SOCKET, unix.SO_BINDTODEVICE, "lo")
	_ = unix.Close(fd)
	if errors.Is(bindErr, unix.EACCES) || errors.Is(bindErr, unix.EPERM) {
		t.Skip("Linux did not allow loopback device binding in this environment")
	}
	if bindErr != nil {
		t.Fatal(bindErr)
	}

	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	dialer := &net.Dialer{ControlContext: func(_ context.Context, _, _ string, raw syscall.RawConn) error {
		return bindProbeSocket(raw, "lo")
	}}
	conn, err := dialer.DialContext(ctx, "tcp4", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	raw, err := conn.(*net.TCPConn).SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var got string
	var readErr error
	if err := raw.Control(func(fd uintptr) {
		got, readErr = unix.GetsockoptString(int(fd), unix.SOL_SOCKET, unix.SO_BINDTODEVICE)
	}); err != nil || readErr != nil || got != "lo" {
		t.Fatalf("socket did not retain loopback identity: got %q, fd error %v, read error %v", got, err, readErr)
	}
	const absent = "rzprobe-missing"
	if _, err := net.InterfaceByName(absent); err == nil {
		t.Fatalf("negative-control interface %q unexpectedly exists", absent)
	}
	for _, device := range []string{"", absent} {
		dialer.ControlContext = func(_ context.Context, _, _ string, raw syscall.RawConn) error {
			return bindProbeSocket(raw, device)
		}
		unbound, err := dialer.DialContext(ctx, "tcp4", listener.Addr().String())
		if unbound != nil {
			_ = unbound.Close()
		}
		if !errors.Is(err, errProbeInterfaceRoute) {
			t.Fatalf("unbound socket with device %q reached connect: %v", device, err)
		}
	}
}
