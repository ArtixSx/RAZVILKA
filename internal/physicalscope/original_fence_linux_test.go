//go:build linux

package physicalscope

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func cleanupFenceTestSocket(t *testing.T, fd int, cookie uint64) {
	t.Helper()
	t.Cleanup(func() {
		if actual, err := unix.GetsockoptUint64(fd, unix.SOL_SOCKET, unix.SO_COOKIE); err == nil && actual == cookie {
			_ = unix.Close(fd)
		}
	})
}

func TestOriginalFenceSocketRetainsActualBufferAndOperationIndependentLifetime(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	opened, err := openFence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	f := opened.(*kernelFence)
	t.Cleanup(func() { _ = f.close() })
	cancel()
	actual, err := unix.GetsockoptInt(f.fd, unix.SOL_SOCKET, unix.SO_RCVBUF)
	if err != nil || actual <= 0 || f.receiveBuffer != actual {
		t.Fatal("requested receive buffer was substituted for actual readback")
	}
	if err := f.currentError(); err != nil {
		t.Fatal("Observe operation cancellation closed the retained descriptor")
	}
	select {
	case <-f.reader.stop:
		t.Fatal("reader lifetime followed the Observe operation context")
	default:
	}
}

func TestOriginalFenceCloseJoinsBeforeClosingOwnedDescriptor(t *testing.T) {
	fd, pid, err := routeSocket(fenceGroups)
	if err != nil {
		t.Fatal(err)
	}
	cookie, err := unix.GetsockoptUint64(fd, unix.SOL_SOCKET, unix.SO_COOKIE)
	if err != nil || cookie == 0 {
		_ = unix.Close(fd)
		t.Fatal("missing actual socket cookie")
	}
	cleanupFenceTestSocket(t, fd, cookie)
	f := &kernelFence{fd: fd, pid: pid, cookie: cookie}
	waiting, release := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	f.reader = newOriginalFenceCollector(fenceCollectorSource{
		current: f.currentError,
		receive: func([]byte) (int, bool, error) { return 0, true, nil },
		wait:    func() error { close(waiting); <-release; return nil },
	})
	t.Cleanup(func() { releaseOnce.Do(func() { close(release) }); _ = f.close() })
	waitFenceTest(t, waiting)
	closed := make(chan struct{})
	go func() { _ = f.close(); close(closed) }()
	waitFenceTest(t, f.reader.stop)
	if err := f.currentError(); err != nil {
		t.Fatal("descriptor closed before original reader joined")
	}
	releaseOnce.Do(func() { close(release) })
	waitFenceTest(t, closed)
	if _, err := unix.GetsockoptUint64(fd, unix.SOL_SOCKET, unix.SO_COOKIE); !errors.Is(err, unix.EBADF) {
		t.Fatal("owned descriptor remained open after reader joined")
	}
	if err := f.close(); err != nil {
		t.Fatal("repeated Close changed original result")
	}
}

func TestOriginalFenceCloseNeverClosesReplacedDescriptor(t *testing.T) {
	fd, pid, err := routeSocket(fenceGroups)
	if err != nil {
		t.Fatal(err)
	}
	cookie, err := unix.GetsockoptUint64(fd, unix.SOL_SOCKET, unix.SO_COOKIE)
	if err != nil || cookie == 0 {
		_ = unix.Close(fd)
		t.Fatal("missing actual socket cookie")
	}
	cleanupFenceTestSocket(t, fd, cookie)
	f := &kernelFence{fd: fd, pid: pid, cookie: cookie}
	f.reader = newOriginalFenceCollector(newFenceTestTransport().source())
	f.reader.close()
	replacement, _, err := routeSocket(fenceGroups)
	if err != nil {
		t.Fatal(err)
	}
	replacementCookie, err := unix.GetsockoptUint64(replacement, unix.SOL_SOCKET, unix.SO_COOKIE)
	if err != nil || replacementCookie == 0 {
		_ = unix.Close(replacement)
		t.Fatal("missing replacement socket cookie")
	}
	cleanupFenceTestSocket(t, replacement, replacementCookie)
	if err := unix.Dup3(replacement, fd, unix.O_CLOEXEC); err != nil {
		t.Fatal(err)
	}
	cleanupFenceTestSocket(t, fd, replacementCookie)
	assertFenceFailure(t, f.close(), "fence.descriptor.cookie.changed")
	if _, err := unix.GetsockoptUint64(fd, unix.SOL_SOCKET, unix.SO_COOKIE); err != nil {
		t.Fatal("Close touched a descriptor that no longer belonged to this fence")
	}
}
