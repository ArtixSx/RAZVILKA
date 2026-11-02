//go:build linux

package dataplane

import (
	"context"
	"errors"
	"net"
	"os"
	"sync"
	"time"

	"github.com/ArtixSx/razvilka/internal/netidentity"
	"golang.org/x/sys/unix"
)

type domainTCPBaselineNative struct {
	self           *domainTCPBaselineNative
	resource       *domainTCPBaselineExecutionResource
	mu             sync.Mutex
	conn           *net.TCPConn
	file, accepted *os.File
	fd             int // Original nonblocking descriptor; os.File.Fd may switch mode.
	closed         bool
	err            error
}

func (n *domainTCPBaselineNative) connection() net.Conn {
	if n == nil || n.self != n {
		return nil
	}
	return n.conn
}

// Neither a tuple nor a caller-supplied dial function reaches this leaf. The
// SAME BF issuer has already reserved the accepted original FD and complete
// original COMMON prerequisites before the one native Connect admission.
func (r *domainTCPBaselineExecutionResource) connectNative(ctx context.Context) (*domainTCPBaselineNative, error) {
	if err := r.checkPrepared(ctx); err != nil {
		return nil, err
	}
	r.mu.Lock()
	if r.entered || r.failure != nil {
		r.mu.Unlock()
		return nil, ErrDomainTCPBaselineKernel
	}
	r.entered = true
	r.mu.Unlock()
	n := &domainTCPBaselineNative{resource: r}
	n.self = n
	r.mu.Lock()
	r.native = n
	r.mu.Unlock()
	s := r.kernel.capture.process.scope
	provider := s.networkIdentity.provider
	err := provider.WithCurrent(ctx, func(held context.Context, identity netidentity.Identity) error {
		if identity != s.networkIdentity.value {
			return ErrDomainTCPBaselineKernel
		}
		raw, err := r.accepted.conn.SyscallConn()
		if err != nil {
			return err
		}
		var duplicate int
		var duplicateErr error
		if err := raw.Control(func(fd uintptr) { duplicate, duplicateErr = unix.FcntlInt(fd, unix.F_DUPFD_CLOEXEC, 0) }); err != nil {
			return err
		}
		if duplicateErr != nil {
			return duplicateErr
		}
		n.accepted = os.NewFile(uintptr(duplicate), "original-domain-accepted-socket")
		if err := r.accepted.current(held, r.kernel.capture.capture, r.accepted.socket); err != nil {
			return err
		}
		fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, unix.IPPROTO_TCP)
		if err != nil {
			return err
		}
		n.file = os.NewFile(uintptr(fd), "original-transparent-domain-baseline")
		n.fd = fd
		if err := unix.SetsockoptInt(fd, unix.SOL_IP, unix.IP_TRANSPARENT, 1); err != nil {
			return err
		}
		if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_MARK, 0x525a0001); err != nil {
			return err
		}
		if err := unix.SetsockoptString(fd, unix.SOL_SOCKET, unix.SO_BINDTODEVICE, r.definition.Egress); err != nil {
			return err
		}
		// Abortive terminal close avoids a detached application stream or a new
		// TIME_WAIT lease after the original handlers have joined.
		if err := unix.SetsockoptLinger(fd, unix.SOL_SOCKET, unix.SO_LINGER, &unix.Linger{Onoff: 1, Linger: 0}); err != nil {
			return err
		}
		source := r.definition.Source.Addr().As4()
		if err := unix.Bind(fd, &unix.SockaddrInet4{Addr: source, Port: int(r.definition.Source.Port())}); err != nil {
			return err
		}
		return nil
	})
	if err == nil {
		err = r.checkPrepared(ctx)
	}
	if err == nil {
		s.startMu.RLock()
		err = func() error {
			defer s.startMu.RUnlock()
			if err := r.registered(ctx); err != nil {
				return err
			}
			return r.kernel.capture.process.material.control.WithStart(ctx, func() error {
				// Only the actual bounded native syscall is inside control admission.
				flags, err := unix.FcntlInt(uintptr(n.fd), unix.F_GETFL, 0)
				if err != nil || flags&unix.O_NONBLOCK == 0 {
					return errors.Join(ErrDomainTCPBaselineKernel, err)
				}
				target := r.definition.Target.Addr().As4()
				connectErr := unix.Connect(n.fd, &unix.SockaddrInet4{Addr: target, Port: int(r.definition.Target.Port())})
				if errors.Is(connectErr, unix.EINPROGRESS) {
					return nil
				}
				return connectErr
			})
		}()
	}
	if err == nil {
		err = domainTCPBaselineWaitConnect(ctx, n.fd)
	}
	if err == nil {
		var c net.Conn
		c, err = net.FileConn(n.file)
		if err == nil {
			var ok bool
			n.conn, ok = c.(*net.TCPConn)
			if !ok {
				_ = c.Close()
				err = ErrDomainTCPBaselineKernel
			}
		}
	}
	if err == nil && (n.conn.LocalAddr().String() != r.definition.Source.String() || n.conn.RemoteAddr().String() != r.definition.Target.String()) {
		err = ErrDomainTCPBaselineKernel
	}
	if err == nil {
		err = r.checkPrepared(ctx)
	}
	if err != nil {
		return n, errors.Join(err, n.closeNative())
	}
	return n, nil
}

func domainTCPBaselineWaitConnect(ctx context.Context, fd int) error {
	deadline, ok := ctx.Deadline()
	if !ok {
		return ErrDomainTCPBaselineKernel
	}
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		left := time.Until(deadline)
		if left <= 0 {
			return context.DeadlineExceeded
		}
		p := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLOUT}}
		n, err := unix.Poll(p, min(20, int((left+time.Millisecond-1)/time.Millisecond)))
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return err
		}
		if n == 0 {
			continue
		}
		if p[0].Revents&(unix.POLLNVAL|unix.POLLHUP) != 0 {
			return ErrDomainTCPBaselineKernel
		}
		code, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_ERROR)
		if err != nil {
			return err
		}
		if code != 0 {
			return unix.Errno(code)
		}
		if p[0].Revents != unix.POLLOUT {
			return ErrDomainTCPBaselineKernel
		}
		return ctx.Err()
	}
}

// Close only original descriptors; no new kernel/path owner is discovered.
// COMMON removal happens afterward and remains mandatory even on cancellation.
func (n *domainTCPBaselineNative) closeNative() error {
	if n == nil || n.self != n {
		return ErrDomainTCPBaselineKernel
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.closed {
		return n.err
	}
	n.closed = true
	if n.conn != nil {
		n.err = errors.Join(n.err, n.conn.Close())
	}
	if n.file != nil {
		n.err = errors.Join(n.err, n.file.Close())
	}
	if n.accepted != nil {
		n.err = errors.Join(n.err, n.accepted.Close())
	}
	return n.err
}
