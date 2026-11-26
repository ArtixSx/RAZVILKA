//go:build linux

package physicalscope

import (
	"errors"
	"sync"

	"golang.org/x/sys/unix"
)

// This socket pair transports scheduling hints only. It is never a kernel
// observation, a receipt or an authority to skip the original netlink drain.
// The collector alone polls/reads. Notifications serialize with final Close;
// both descriptors remain held until the original collector has joined.
type fenceWake struct {
	self     *fenceWake
	mu       sync.Mutex
	fds      [2]int
	cookies  [2]uint64
	closed   bool
	closeErr error
}

func newFenceWake() (*fenceWake, error) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, boundary("fence.wake.open", err)
	}
	w := &fenceWake{fds: fds}
	w.self = w
	for i, fd := range fds {
		cookie, err := unix.GetsockoptUint64(fd, unix.SOL_SOCKET, unix.SO_COOKIE)
		if err != nil || cookie == 0 {
			return nil, errors.Join(at("fence.wake.cookie", err), unix.Close(fds[0]), unix.Close(fds[1]))
		}
		w.cookies[i] = cookie
	}
	return w, nil
}

func (w *fenceWake) current(i int) error {
	if w == nil || w.self != w || i < 0 || i > 1 {
		return at("fence.wake.owner", nil)
	}
	cookie, err := unix.GetsockoptUint64(w.fds[i], unix.SOL_SOCKET, unix.SO_COOKIE)
	if err != nil || cookie == 0 || cookie != w.cookies[i] {
		return at("fence.wake.identity", err)
	}
	return nil
}

func (w *fenceWake) notify() error {
	if w == nil || w.self != w {
		return at("fence.wake.owner", nil)
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return at("fence.wake.closed", w.closeErr)
	}
	if err := w.current(1); err != nil {
		return err
	}
	n, err := unix.Write(w.fds[1], []byte{1})
	if err == unix.EAGAIN || err == unix.EWOULDBLOCK {
		return w.current(1) // A full queue already guarantees a wake, not a read ACK.
	}
	if err != nil || n != 1 {
		return at("fence.wake.notify", err)
	}
	return w.current(1)
}

func (w *fenceWake) wait(original int) error {
	if err := w.current(0); err != nil {
		return err
	}
	poll := []unix.PollFd{{Fd: int32(original), Events: unix.POLLIN}, {Fd: int32(w.fds[0]), Events: unix.POLLIN}}
	if _, err := unix.Poll(poll, 20); err != nil && err != unix.EINTR {
		return boundary("fence.poll.read", err)
	}
	if poll[0].Revents&(unix.POLLHUP|unix.POLLNVAL) != 0 {
		return at("fence.poll.descriptor", nil)
	}
	// Netlink POLLERR still goes to the sole original receive (ENOBUFS etc.).
	if poll[1].Revents & ^int16(unix.POLLIN) != 0 {
		return at("fence.wake.poll", nil)
	}
	if err := w.current(0); err != nil {
		return err
	}
	if poll[1].Revents&unix.POLLIN == 0 {
		return nil
	}
	var buf [2]byte
	for range 64 {
		n, err := unix.Read(w.fds[0], buf[:])
		if err == unix.EAGAIN || err == unix.EWOULDBLOCK {
			return w.current(0)
		}
		if err != nil || n != 1 || buf[0] != 1 {
			return at("fence.wake.read", err)
		}
	}
	// Further hints stay queued. The next iteration handles the real checkpoint
	// and performs its complete drain regardless of how many hints coalesced.
	return w.current(0)
}

func (w *fenceWake) close() error {
	if w == nil || w.self != w {
		return at("fence.wake.owner", nil)
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.closed {
		w.closed = true
		for i, fd := range w.fds {
			if err := w.current(i); err != nil {
				w.closeErr = errors.Join(w.closeErr, err) // Never close a replacement.
			} else {
				w.closeErr = errors.Join(w.closeErr, unix.Close(fd))
			}
		}
	}
	return w.closeErr
}
