//go:build linux

package dataplane

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"

	"golang.org/x/sys/unix"
)

var errPublicTCPBaselineSocket = errors.New("original-public-tcp-baseline-socket-unavailable")

// A prepared descriptor, never an outbound grant. Preparation binds the
// actual accepted source to a fresh kernel port before the original owner
// compiles its exact return selector. No production Connect API exists here.
// The original COMMON resource must retain this descriptor through all native
// Connect/flow joins; a tuple, DTO or copied struct cannot replace that owner.
type publicTCPBaselineSocket struct {
	self     *publicTCPBaselineSocket
	mu       sync.Mutex
	fd       int
	stat     unix.Stat_t
	source   netip.AddrPort
	captured DomainPolicyTCPSocket
	accepted *net.TCPConn
	issuer   context.Context
	closed   bool
}

func preparePublicTCPBaselineSocket(ctx context.Context, accepted *net.TCPConn) (result *publicTCPBaselineSocket, err error) {
	if ctx == nil || accepted == nil {
		return nil, errPublicTCPBaselineSocket
	}
	if err := ctx.Err(); err != nil {
		return nil, errors.Join(errPublicTCPBaselineSocket, err)
	}
	if _, finite := ctx.Deadline(); !finite {
		return nil, errPublicTCPBaselineSocket
	}
	captured, err := observeDomainPolicyTCPSocket(accepted)
	if err != nil || !captured.Source.Addr().Is4() || !captured.Source.Addr().IsGlobalUnicast() || captured.Source.Addr().IsLoopback() || !domainPolicyTCPPublicIPv4(captured.OriginalDestination.Addr()) || (captured.OriginalDestination.Port() != 80 && captured.OriginalDestination.Port() != 443) {
		return nil, errors.Join(errPublicTCPBaselineSocket, err)
	}
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, unix.IPPROTO_TCP)
	if err != nil {
		return nil, errors.Join(errPublicTCPBaselineSocket, err)
	}
	defer func() {
		if result == nil {
			_ = unix.Close(fd)
		}
	}()
	if err = unix.SetsockoptInt(fd, unix.SOL_IP, unix.IP_TRANSPARENT, 1); err != nil {
		return nil, errors.Join(errPublicTCPBaselineSocket, err)
	}
	if err = unix.Bind(fd, &unix.SockaddrInet4{Addr: captured.Source.Addr().As4()}); err != nil {
		return nil, errors.Join(errPublicTCPBaselineSocket, err)
	}
	bound, err := unix.Getsockname(fd)
	if err != nil {
		return nil, errors.Join(errPublicTCPBaselineSocket, err)
	}
	address, ok := bound.(*unix.SockaddrInet4)
	if !ok || address.Port < 1024 || address.Port == int(captured.Source.Port()) || address.Addr != captured.Source.Addr().As4() {
		return nil, errPublicTCPBaselineSocket
	}
	prepared := &publicTCPBaselineSocket{fd: fd, source: netip.AddrPortFrom(netip.AddrFrom4(address.Addr), uint16(address.Port)), captured: captured, accepted: accepted, issuer: ctx}
	prepared.self = prepared
	if err = unix.Fstat(fd, &prepared.stat); err != nil || prepared.stat.Mode&unix.S_IFMT != unix.S_IFSOCK || prepared.stat.Ino == 0 {
		return nil, errors.Join(errPublicTCPBaselineSocket, err)
	}
	if err = prepared.current(ctx); err != nil {
		return nil, err
	}
	return prepared, nil
}
func (s *publicTCPBaselineSocket) current(ctx context.Context) error {
	if s == nil || s.self != s || ctx == nil || s.issuer == nil {
		return errPublicTCPBaselineSocket
	}
	if err := ctx.Err(); err != nil {
		return errors.Join(errPublicTCPBaselineSocket, err)
	}
	if _, finite := ctx.Deadline(); !finite {
		return errPublicTCPBaselineSocket
	}
	if err := s.issuer.Err(); err != nil {
		return errors.Join(errPublicTCPBaselineSocket, err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.fd < 0 || s.accepted == nil {
		return errPublicTCPBaselineSocket
	}
	actual, err := observeDomainPolicyTCPSocket(s.accepted)
	if err != nil || actual != s.captured {
		return errors.Join(errPublicTCPBaselineSocket, err)
	}
	var stat unix.Stat_t
	if err = unix.Fstat(s.fd, &stat); err != nil || stat.Dev != s.stat.Dev || stat.Ino != s.stat.Ino || stat.Mode&unix.S_IFMT != unix.S_IFSOCK {
		return errors.Join(errPublicTCPBaselineSocket, err)
	}
	local, err := unix.Getsockname(s.fd)
	if err != nil {
		return errors.Join(errPublicTCPBaselineSocket, err)
	}
	bound, ok := local.(*unix.SockaddrInet4)
	if !ok || bound.Addr != s.source.Addr().As4() || bound.Port != int(s.source.Port()) {
		return errPublicTCPBaselineSocket
	}
	flags, err := unix.FcntlInt(uintptr(s.fd), unix.F_GETFD, 0)
	if err != nil || flags&unix.FD_CLOEXEC == 0 {
		return errors.Join(errPublicTCPBaselineSocket, err)
	}
	status, err := unix.FcntlInt(uintptr(s.fd), unix.F_GETFL, 0)
	if err != nil || status&unix.O_NONBLOCK == 0 {
		return errors.Join(errPublicTCPBaselineSocket, err)
	}
	peer, peerErr := unix.Getpeername(s.fd)
	if peerErr == nil {
		remote, ok := peer.(*unix.SockaddrInet4)
		if !ok || remote.Addr != s.captured.OriginalDestination.Addr().As4() || remote.Port != int(s.captured.OriginalDestination.Port()) {
			return errPublicTCPBaselineSocket
		}
	} else if !errors.Is(peerErr, unix.ENOTCONN) {
		return errors.Join(errPublicTCPBaselineSocket, peerErr)
	}
	transparent, err := unix.GetsockoptInt(s.fd, unix.SOL_IP, unix.IP_TRANSPARENT)
	if err != nil || transparent != 1 {
		return errors.Join(errPublicTCPBaselineSocket, err)
	}
	mark, err := unix.GetsockoptInt(s.fd, unix.SOL_SOCKET, unix.SO_MARK)
	if err != nil || mark != 0 {
		return errors.Join(errPublicTCPBaselineSocket, err)
	}
	if err := s.issuer.Err(); err != nil {
		return errors.Join(errPublicTCPBaselineSocket, err)
	}
	return ctx.Err()
}
func (s *publicTCPBaselineSocket) close() error {
	if s == nil || s.self != s {
		return errPublicTCPBaselineSocket
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	fd := s.fd
	s.fd = -1
	return unix.Close(fd)
}
