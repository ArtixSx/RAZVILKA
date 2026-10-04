package dataplane

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"strconv"
	"strings"
)

type nodeRouterBackendSocket struct {
	local, remote netip.AddrPort
	state, inode  string
}

func nodeRouterProcEndpoint(raw string, ipv6 bool) (netip.AddrPort, error) {
	parts := strings.Split(raw, ":")
	size := 8
	if ipv6 {
		size = 32
	}
	if len(parts) != 2 || len(parts[0]) != size || len(parts[1]) != 4 {
		return netip.AddrPort{}, ErrNodeTransitUnavailable
	}
	port, err := strconv.ParseUint(parts[1], 16, 16)
	if err != nil {
		return netip.AddrPort{}, ErrNodeTransitUnavailable
	}
	var bytes [16]byte
	for i := 0; i < size/8; i++ {
		word, err := strconv.ParseUint(parts[0][i*8:(i+1)*8], 16, 32)
		if err != nil {
			return netip.AddrPort{}, ErrNodeTransitUnavailable
		}
		binary.NativeEndian.PutUint32(bytes[i*4:i*4+4], uint32(word))
	}
	address := netip.AddrFrom16(bytes)
	if !ipv6 {
		address = netip.AddrFrom4([4]byte{bytes[0], bytes[1], bytes[2], bytes[3]})
	}
	return netip.AddrPortFrom(address.Unmap(), uint16(port)), nil
}

// Only sockets held by the already verified process are considered. An inode
// present in its namespace's table without an owned fd conveys no ownership.
func nodeRouterOwnedSockets(raw []byte, ipv6 bool, inodes map[string]bool) ([]nodeRouterBackendSocket, error) {
	if len(raw) > 1<<20 || len(inodes) > 2048 || strings.ContainsRune(string(raw), '\x00') {
		return nil, ErrNodeTransitUnavailable
	}
	lines := strings.Split(string(raw), "\n")
	if len(lines) > 8192 {
		return nil, ErrNodeTransitUnavailable
	}
	var sockets []nodeRouterBackendSocket
	seen := map[string]bool{}
	for index, line := range lines {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if index == 0 && fields[0] == "sl" {
			continue
		}
		if len(fields) < 10 {
			return nil, ErrNodeTransitUnavailable
		}
		inode := fields[9]
		if !inodes[inode] {
			continue
		}
		if seen[inode] || len(fields[3]) != 2 {
			return nil, ErrNodeTransitUnavailable
		}
		seen[inode] = true
		local, e1 := nodeRouterProcEndpoint(fields[1], ipv6)
		remote, e2 := nodeRouterProcEndpoint(fields[2], ipv6)
		if e1 != nil || e2 != nil {
			return nil, ErrNodeTransitUnavailable
		}
		sockets = append(sockets, nodeRouterBackendSocket{local: local, remote: remote, state: fields[3], inode: inode})
	}
	return sockets, nil
}

func nodeRouterSocketDisjoint(socket nodeRouterBackendSocket, source, pin netip.Addr, endpoints map[netip.Addr]bool) error {
	if !socket.local.IsValid() || !socket.remote.IsValid() || socket.local.Addr() == source || socket.remote.Addr() == pin {
		return ErrNodeTransitUnavailable
	}
	if socket.remote.Addr().IsUnspecified() {
		// Only the exact loopback TCP listener is safe without a remote peer.
		if socket.state != "0A" || !socket.local.Addr().IsLoopback() || socket.remote.Port() != 0 {
			return errors.New("unconnected backend socket has no exact remote isolation proof")
		}
		return nil
	}
	if socket.local.Addr().IsLoopback() && socket.remote.Addr().IsLoopback() {
		return nil
	}
	if !endpoints[socket.remote.Addr()] || socket.remote.Port() == 0 {
		return ErrNodeTransitUnavailable
	}
	return nil
}

// NETLINK_ROUTE control sockets are used by the owned sidecar's interface
// monitor. They cannot carry an IPv4/IPv6 packet through RPDB. Other protocols
// and unclassified socket inodes remain unsupported.
func nodeRouterOwnedRouteNetlink(raw []byte, inodes map[string]bool) (map[string]bool, error) {
	if len(raw) > 1<<20 || strings.ContainsRune(string(raw), '\x00') {
		return nil, ErrNodeTransitUnavailable
	}
	lines := strings.Split(string(raw), "\n")
	if len(lines) > 8192 {
		return nil, ErrNodeTransitUnavailable
	}
	result := map[string]bool{}
	for i, line := range lines {
		fields := strings.Fields(line)
		if len(fields) == 0 || i == 0 && fields[0] == "sk" {
			continue
		}
		if len(fields) != 10 {
			return nil, ErrNodeTransitUnavailable
		}
		inode := fields[9]
		if !inodes[inode] {
			continue
		}
		if fields[1] != "0" || result[inode] {
			return nil, ErrNodeTransitUnavailable
		}
		for _, index := range []int{2, 4, 5, 6, 7, 8, 9} {
			value, err := strconv.ParseUint(fields[index], 10, 64)
			if err != nil || strconv.FormatUint(value, 10) != fields[index] {
				return nil, ErrNodeTransitUnavailable
			}
		}
		if _, err := strconv.ParseUint(fields[3], 16, 32); err != nil {
			return nil, ErrNodeTransitUnavailable
		}
		result[inode] = true
	}
	return result, nil
}
