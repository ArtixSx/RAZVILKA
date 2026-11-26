//go:build linux

package dataplane

import (
	"encoding/binary"
	"net"
	"net/netip"

	"golang.org/x/sys/unix"
)

func domainPolicyTCPCaptureSupported() bool { return true }

func observeDomainPolicyTCPSocket(conn *net.TCPConn) (DomainPolicyTCPSocket, error) {
	var socket DomainPolicyTCPSocket
	peer, ok := conn.RemoteAddr().(*net.TCPAddr)
	local, localOK := conn.LocalAddr().(*net.TCPAddr)
	if !ok || !localOK || !peer.AddrPort().Addr().Is4() || !local.AddrPort().Addr().Is4() {
		return socket, ErrDomainPolicyTCPConsumer
	}
	socket.Source, socket.Listener = peer.AddrPort(), local.AddrPort()
	raw, err := conn.SyscallConn()
	if err != nil {
		return socket, err
	}
	var originalErr error
	err = raw.Control(func(fd uintptr) {
		// GetsockoptIPv6Mreq supplies a buffer larger than sockaddr_in. At
		// SOL_IP this option returns sockaddr_in, not an IPv6 membership.
		// Decode that native AF_INET image; never use getsockname as fallback.
		image, e := unix.GetsockoptIPv6Mreq(int(fd), unix.SOL_IP, unix.SO_ORIGINAL_DST)
		if e != nil {
			originalErr = e
			return
		}
		if binary.NativeEndian.Uint16(image.Multiaddr[:2]) != unix.AF_INET {
			originalErr = ErrDomainPolicyTCPConsumer
			return
		}
		ip := netip.AddrFrom4([4]byte(image.Multiaddr[4:8]))
		socket.OriginalDestination = netip.AddrPortFrom(ip, binary.BigEndian.Uint16(image.Multiaddr[2:4]))
	})
	if err != nil {
		return socket, err
	}
	return socket, originalErr
}
