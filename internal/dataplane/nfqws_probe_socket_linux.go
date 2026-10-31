//go:build linux

package dataplane

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"
)

// Descriptor-only leaf, not an Execution resource or a flow admission grant.
type nfqwsProbeBoundSocket struct {
	self                *nfqwsProbeBoundSocket
	mu                  sync.Mutex
	fd                  int
	stat                unix.Stat_t
	source, destination netip.AddrPort
	closed              bool
	closeFailed         bool
}

func (r *nfqwsProbeBoundSocket) metadata() (netip.AddrPort, netip.AddrPort, uint64, uint64, error) {
	if r == nil || r.self != r {
		return netip.AddrPort{}, netip.AddrPort{}, 0, 0, errNFQWSProbeSocket
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return netip.AddrPort{}, netip.AddrPort{}, 0, 0, errNFQWSProbeSocket
	}
	return r.source, r.destination, uint64(r.stat.Dev), r.stat.Ino, nil
}

func nfqwsProbeRouteSource(ctx context.Context, destination netip.AddrPort) (netip.Addr, error) {
	if ctx == nil || ctx.Err() != nil || !domainPolicyTCPPublicIPv4(destination.Addr()) || destination.Port() != 443 {
		return netip.Addr{}, errNFQWSProbeSocket
	}
	// UDP Connect chooses a route/local source without sending an application
	// packet. No write occurs; this temporary observer never enters NFQUEUE.
	conn, err := (&net.Dialer{}).DialContext(ctx, "udp4", destination.String())
	if err != nil {
		return netip.Addr{}, errors.Join(errNFQWSProbeSocket, err)
	}
	defer conn.Close()
	local, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok {
		return netip.Addr{}, errNFQWSProbeSocket
	}
	address, ok := netip.AddrFromSlice(local.IP)
	if !ok || !address.Unmap().Is4() || address.IsUnspecified() || address.IsLoopback() {
		return netip.Addr{}, errNFQWSProbeSocket
	}
	return address.Unmap(), ctx.Err()
}

func prepareNFQWSProbeBoundSocket(ctx context.Context, raw syscall.RawConn, source netip.Addr, destination netip.AddrPort) (result *nfqwsProbeBoundSocket, err error) {
	if ctx == nil || ctx.Err() != nil || raw == nil || !source.Is4() || !domainPolicyTCPPublicIPv4(destination.Addr()) || destination.Port() != 443 {
		return nil, errNFQWSProbeSocket
	}
	fd := -1
	var inner error
	if err := raw.Control(func(original uintptr) {
		for _, option := range []int{unix.SO_REUSEADDR, unix.SO_REUSEPORT} {
			if value, e := unix.GetsockoptInt(int(original), unix.SOL_SOCKET, option); e != nil || value != 0 {
				inner = errNFQWSProbeSocket
				return
			}
		}
		if value, e := unix.GetsockoptInt(int(original), unix.SOL_SOCKET, unix.SO_TYPE); e != nil || value != unix.SOCK_STREAM {
			inner = errNFQWSProbeSocket
			return
		}
		if value, e := unix.GetsockoptInt(int(original), unix.SOL_IP, unix.IP_TRANSPARENT); e != nil || value != 0 {
			inner = errNFQWSProbeSocket
			return
		}
		if value, e := unix.GetsockoptInt(int(original), unix.SOL_SOCKET, unix.SO_MARK); e != nil || value != 0 {
			inner = errNFQWSProbeSocket
			return
		}
		if _, e := unix.Getpeername(int(original)); !errors.Is(e, unix.ENOTCONN) {
			inner = errNFQWSProbeSocket
			return
		}
		if e := unix.Bind(int(original), &unix.SockaddrInet4{Addr: source.As4()}); e != nil {
			inner = e
			return
		}
		fd, inner = unix.FcntlInt(original, unix.F_DUPFD_CLOEXEC, 0)
	}); err != nil {
		return nil, errors.Join(errNFQWSProbeSocket, err)
	}
	if inner != nil || fd < 0 {
		return nil, errors.Join(errNFQWSProbeSocket, inner)
	}
	defer func() {
		if result == nil {
			_ = unix.Close(fd)
		}
	}()
	bound, err := unix.Getsockname(fd)
	if err != nil {
		return nil, err
	}
	local, ok := bound.(*unix.SockaddrInet4)
	if !ok || local.Addr != source.As4() || local.Port < 1024 {
		return nil, errNFQWSProbeSocket
	}
	s := &nfqwsProbeBoundSocket{fd: fd, source: netip.AddrPortFrom(source, uint16(local.Port)), destination: destination}
	s.self = s
	if err := unix.Fstat(fd, &s.stat); err != nil || s.stat.Mode&unix.S_IFMT != unix.S_IFSOCK || s.stat.Ino == 0 {
		return nil, errors.Join(errNFQWSProbeSocket, err)
	}
	if err := s.current(ctx); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *nfqwsProbeBoundSocket) current(ctx context.Context) error {
	return s.check(ctx, true)
}

func (s *nfqwsProbeBoundSocket) retainedCurrent(ctx context.Context) error {
	return s.check(ctx, false)
}

func (s *nfqwsProbeBoundSocket) check(ctx context.Context, forward bool) error {
	if s == nil || s.self != s || ctx == nil || ctx.Err() != nil {
		return errNFQWSProbeSocket
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.fd < 0 {
		return errNFQWSProbeSocket
	}
	var stat unix.Stat_t
	if err := unix.Fstat(s.fd, &stat); err != nil || stat.Ino != s.stat.Ino || stat.Dev != s.stat.Dev || stat.Mode&unix.S_IFMT != unix.S_IFSOCK {
		return errNFQWSProbeSocket
	}
	bound, err := unix.Getsockname(s.fd)
	if err != nil {
		return err
	}
	local, ok := bound.(*unix.SockaddrInet4)
	if !ok || local.Addr != s.source.Addr().As4() || local.Port != int(s.source.Port()) {
		return errNFQWSProbeSocket
	}
	if peer, err := unix.Getpeername(s.fd); err == nil {
		remote, ok := peer.(*unix.SockaddrInet4)
		if !ok || remote.Addr != s.destination.Addr().As4() || remote.Port != int(s.destination.Port()) {
			return errNFQWSProbeSocket
		}
	} else if !errors.Is(err, unix.ENOTCONN) {
		return errNFQWSProbeSocket
	}
	if mark, err := unix.GetsockoptInt(s.fd, unix.SOL_SOCKET, unix.SO_MARK); err != nil || mark != 0 {
		return errNFQWSProbeSocket
	}
	for _, option := range []int{unix.SO_REUSEADDR, unix.SO_REUSEPORT} {
		if value, err := unix.GetsockoptInt(s.fd, unix.SOL_SOCKET, option); err != nil || value != 0 {
			return errNFQWSProbeSocket
		}
	}
	if transparent, err := unix.GetsockoptInt(s.fd, unix.SOL_IP, unix.IP_TRANSPARENT); err != nil || transparent != 0 {
		return errNFQWSProbeSocket
	}
	if flags, err := unix.FcntlInt(uintptr(s.fd), unix.F_GETFD, 0); err != nil || flags&unix.FD_CLOEXEC == 0 {
		return errNFQWSProbeSocket
	}
	if flags, err := unix.FcntlInt(uintptr(s.fd), unix.F_GETFL, 0); err != nil || flags&unix.O_NONBLOCK == 0 {
		return errNFQWSProbeSocket
	}
	if forward {
		source, err := nfqwsProbeRouteSource(ctx, s.destination)
		if err != nil || source != s.source.Addr() {
			return errNFQWSProbeSocket
		}
	}
	return ctx.Err()
}

func (s *nfqwsProbeBoundSocket) close() error {
	if s == nil || s.self != s {
		return errNFQWSProbeSocket
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	if s.closeFailed {
		return errNFQWSProbeSocket
	}
	var current unix.Stat_t
	if err := unix.Fstat(s.fd, &current); err != nil || current.Dev != s.stat.Dev || current.Ino != s.stat.Ino {
		return errors.Join(errNFQWSProbeSocket, err)
	}
	if err := unix.Close(s.fd); err != nil {
		s.closeFailed = true // Never retry an ambiguous fd number after port reuse.
		return err
	}
	s.closed = true
	s.fd = -1
	return nil
}
