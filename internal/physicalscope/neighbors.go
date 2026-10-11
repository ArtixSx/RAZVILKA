package physicalscope

import (
	"bytes"
	"context"
	"encoding/binary"
	"net"
	"net/netip"
	"slices"
	"strings"
)

type kernelNeighbor struct {
	index       int
	address     netip.Addr
	mac         string
	state       uint16
	flags, kind byte
}

func (n kernelNeighbor) row() string {
	row := n.address.String()
	if n.mac != "" {
		row += " lladdr " + n.mac
	}
	return row + " " + neighborState(n.state) + "\n"
}

func neighborState(state uint16) string {
	return map[uint16]string{1: "INCOMPLETE", 2: "REACHABLE", 4: "STALE", 8: "DELAY", 16: "PROBE", 32: "FAILED", 64: "NOARP", 128: "PERMANENT"}[state]
}

func parseKernelNeighbor(m message) (kernelNeighbor, error) {
	fail := func(stage string) (kernelNeighbor, error) {
		return kernelNeighbor{}, at("kernel.bindings.neighbor."+stage, nil)
	}
	if len(m.data) < 12 {
		return fail("header")
	}
	if m.data[0] != 2 && m.data[0] != 10 {
		return fail("family")
	}
	a, err := attrs(m.data[12:])
	if err != nil {
		return kernelNeighbor{}, at("kernel.bindings.neighbor.attributes", err)
	}
	n := kernelNeighbor{index: int(int32(binary.NativeEndian.Uint32(m.data[4:8]))), state: binary.NativeEndian.Uint16(m.data[8:10]), flags: m.data[10], kind: m.data[11], mac: net.HardwareAddr(a[2]).String()}
	if n.index <= 0 {
		return fail("index")
	}
	var ok bool
	n.address, ok = netip.AddrFromSlice(a[1])
	if !ok || n.address.Is4In6() || n.address.Is4() != (m.data[0] == 2) || n.address.IsUnspecified() || n.address.IsLoopback() {
		return fail("address")
	}
	if neighborState(n.state) == "" {
		return fail("state")
	}
	if n.flags&^(byte(2|16|128)) != 0 {
		return fail("flags")
	}
	if n.flags&128 != 0 && (!n.address.Is6() || n.address.IsMulticast()) {
		return fail("router-flag")
	}
	if n.kind == 3 || n.kind == 5 {
		for kind, value := range a {
			if kind == 1 || kind == 2 {
				continue
			}
			if kind == 0 && len(value) == 0 || kind == 3 && len(value) == 16 || kind == 4 && len(value) == 4 {
				continue
			}
			return fail("bookkeeping-attributes")
		}
	}
	return n, nil
}

// The caller must first prove this ifindex is OUTSIDE the selected L3 segments.
// Actual stock NC1812 emits precisely these IPv4 zero-destination NOARP
// RTN_BROADCAST rows with an empty or all-zero Ethernet address. Neither can
// identify a protected canonical unicast MAC or a valid bound LAN address.
// Selected segments always use the unchanged strict decoder instead.
func decodeForeignKernelNeighbor(m message) (kernelNeighbor, bool, error) {
	n, originalErr := parseKernelNeighbor(m)
	if originalErr == nil {
		return n, false, nil
	}
	if (m.kind != 28 && m.kind != 29) || len(m.data) < 12 || m.data[0] != 2 || binary.NativeEndian.Uint16(m.data[8:10]) != 64 || m.data[10] != 0 || m.data[11] != 3 {
		return kernelNeighbor{}, false, originalErr
	}
	index := int(int32(binary.NativeEndian.Uint32(m.data[4:8])))
	a, err := attrs(m.data[12:])
	_, hasLLAddress := a[2]
	if index <= 0 || err != nil || len(a) != 4 || !hasLLAddress || !bytes.Equal(a[1], []byte{0, 0, 0, 0}) || len(a[3]) != 16 || len(a[4]) != 4 || len(a[2]) != 0 && !bytes.Equal(a[2], []byte{0, 0, 0, 0, 0, 0}) {
		return kernelNeighbor{}, false, originalErr
	}
	return kernelNeighbor{index: index, address: netip.IPv4Unspecified(), mac: net.HardwareAddr(a[2]).String(), state: 64, kind: 3}, true, nil
}

func validateUnicastNeighbor(n kernelNeighbor) error {
	if n.address.IsMulticast() {
		return at("kernel.bindings.neighbor.address", nil)
	}
	if n.kind != 1 {
		return at("kernel.bindings.neighbor.type", nil)
	}
	if n.state != 1 && n.state != 32 && !validMAC(n.mac) {
		return at("kernel.bindings.neighbor.mac", nil)
	}
	// An unresolved router cannot supply a negative MAC binding. Hold rather
	// than guessing which other mappings must remain outside client identity.
	if n.flags&128 != 0 && (n.state == 1 || n.state == 32) {
		return at("kernel.bindings.neighbor.router-state", nil)
	}
	return nil
}

// Same classifier for initial/current dumps and multicast notifications.
// A bookkeeping tuple must match address class, exact Ethernet mapping, NOARP,
// zero flags, type and the already corroborated selected segment/prefix.
func decodeSegmentNeighbor(m message, s Segment) (kernelNeighbor, bool, error) {
	n, err := parseKernelNeighbor(m)
	if err != nil {
		return n, false, err
	}
	if n.index != s.IfIndex {
		return n, false, at("kernel.bindings.neighbor.segment", nil)
	}
	if n.kind == 3 || n.kind == 5 {
		if n.state != 64 || n.flags != 0 {
			return n, false, at("kernel.bindings.neighbor.bookkeeping-state", nil)
		}
		mac, err := net.ParseMAC(n.mac)
		if err != nil || len(mac) != 6 {
			return n, false, at("kernel.bindings.neighbor.bookkeeping-mac", nil)
		}
		if n.kind == 5 {
			if !n.address.IsMulticast() || !bytes.Equal(mac, multicastMAC(n.address)) {
				return n, false, at("kernel.bindings.neighbor.multicast-tuple", nil)
			}
		} else {
			if !n.address.Is4() || !bytes.Equal(mac, []byte{255, 255, 255, 255, 255, 255}) {
				return n, false, at("kernel.bindings.neighbor.broadcast-tuple", nil)
			}
			ok, err := selectedBroadcast(n.address, s.Prefixes)
			if err != nil || !ok {
				return n, false, at("kernel.bindings.neighbor.broadcast-prefix", err)
			}
		}
		return n, true, nil
	}
	if n.kind == 1 && n.address.Is4() {
		broadcast, err := selectedBroadcast(n.address, s.Prefixes)
		if err != nil {
			return n, false, at("kernel.bindings.neighbor.broadcast-prefix", err)
		}
		if broadcast {
			return n, false, at("kernel.bindings.neighbor.broadcast-type", nil)
		}
	}
	return n, false, validateUnicastNeighbor(n)
}

func multicastMAC(address netip.Addr) []byte {
	if address.Is4() {
		a := address.As4()
		return []byte{1, 0, 0x5e, a[1] & 0x7f, a[2], a[3]}
	}
	a := address.As16()
	return []byte{0x33, 0x33, a[12], a[13], a[14], a[15]}
}

// Linux fib_add_ifaddr installs both first/last IPv4 prefix endpoints as
// RTN_BROADCAST when prefixlen<31. Limited broadcast has its fixed IPv4 tuple.
// Custom/off-prefix broadcast and ambiguous prefixes remain unsupported.
func selectedBroadcast(address netip.Addr, prefixes []string) (bool, error) {
	if address == netip.AddrFrom4([4]byte{255, 255, 255, 255}) {
		return true, nil
	}
	matches := 0
	for _, raw := range prefixes {
		p, err := netip.ParsePrefix(raw)
		if err != nil || p != p.Masked() {
			return false, ErrUnknown
		}
		if !p.Addr().Is4() || p.Bits() >= 31 {
			continue
		}
		first := p.Addr().As4()
		last := binary.BigEndian.Uint32(first[:]) | ^uint32(0)>>p.Bits()
		var bytes [4]byte
		binary.BigEndian.PutUint32(bytes[:], last)
		if address == p.Addr() || address == netip.AddrFrom4(bytes) {
			matches++
		}
	}
	return matches == 1, nil
}

// Input is the actual bounded kernel dump. Router role suppresses the entire
// observed MAC from client identity, retaining every active mapping and its
// ORIGINAL flags separately. It does not invent a router bit on other addresses.
func bindKernelNeighbors(ctx context.Context, segments []Segment, frames map[byte][]message) ([]Device, error) {
	return bindSelectedKernelNeighbors(ctx, Selection{}, segments, frames)
}

func bindSelectedKernelNeighbors(ctx context.Context, selection Selection, segments []Segment, frames map[byte][]message) ([]Device, error) {
	intentMACs, err := projectionIntentMACs(selection.SelectedDevices)
	if err != nil {
		return nil, err
	}
	rows := kernelNeighborRows{}
	byIndex := map[int]int{}
	for i, s := range segments {
		rows[s.Interface] = map[bool][]byte{false: {}, true: {}}
		byIndex[s.IfIndex] = i
		segments[i].RouterNeighbors = nil
	}
	var neighbors []kernelNeighbor
	var foreignNeighbors []kernelNeighbor
	routerMACs := map[string]bool{}
	seen := map[string]bool{}
	totalBytes, totalRecords := 0, 0
	for _, family := range []byte{2, 10} {
		messages, ok := frames[family]
		if !ok {
			return nil, at("kernel.bindings.neighbor.family-missing", nil)
		}
		for _, m := range messages {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			if len(m.data) < 12 {
				return nil, at("kernel.bindings.neighbor.header", nil)
			}
			position, selected := byIndex[int(binary.NativeEndian.Uint32(m.data[4:8]))]
			if !selected {
				// IP-neighbor evidence of a cohort MAC on another ingress is
				// relevant even though that bridge is not a selected segment.
				if selection.SelectedDevices != nil && (m.data[0] == 2 || m.data[0] == 10) {
					if m.data[0] != family {
						return nil, at("kernel.bindings.neighbor.dump-family", nil)
					}
					n, bookkeeping, err := decodeForeignKernelNeighbor(m)
					if err != nil {
						return nil, err
					}
					if intentMACs[n.mac] {
						return nil, at("projection.bindings.ingress", nil)
					}
					totalBytes += len(n.row())
					totalRecords++
					if totalBytes > 1<<20 || totalRecords > 4096 {
						return nil, at("kernel.bindings.neighbor.limit", nil)
					}
					if bookkeeping {
						continue
					}
					foreignNeighbors = append(foreignNeighbors, n)
				}
				continue
			}
			if m.data[0] != family {
				return nil, at("kernel.bindings.neighbor.dump-family", nil)
			}
			n, bookkeeping, err := decodeSegmentNeighbor(m, segments[position])
			if err != nil {
				return nil, err
			}
			totalBytes += len(n.row())
			totalRecords++
			if totalBytes > 1<<20 || totalRecords > 4096 {
				return nil, at("kernel.bindings.neighbor.limit", nil)
			}
			key := segments[position].Interface + "\x00" + n.address.String()
			if seen[key] {
				return nil, at("kernel.bindings.neighbor.duplicate", nil)
			}
			seen[key] = true
			if bookkeeping {
				continue
			}
			neighbors = append(neighbors, n)
			if n.flags&128 != 0 {
				routerMACs[n.mac] = true
			}
		}
	}
	wanted, err := validateProjectedNeighbors(selection.SelectedDevices, segments, neighbors, foreignNeighbors, routerMACs)
	if err != nil {
		return nil, err
	}
	for _, n := range neighbors {
		position := byIndex[n.index]
		if routerMACs[n.mac] {
			if n.state != 1 && n.state != 32 {
				segments[position].RouterNeighbors = append(segments[position].RouterNeighbors, RouterNeighbor{Address: n.address.String(), MAC: n.mac, Flags: n.flags, Type: n.kind})
			}
			continue
		}
		if selection.SelectedDevices != nil && !wanted[n.mac] {
			continue
		}
		family := n.address.Is6()
		rows[segments[position].Interface][family] = append(rows[segments[position].Interface][family], []byte(n.row())...)
	}
	for i := range segments {
		slices.SortFunc(segments[i].RouterNeighbors, func(a, b RouterNeighbor) int {
			if n := strings.Compare(a.Address, b.Address); n != 0 {
				return n
			}
			return strings.Compare(a.MAC, b.MAC)
		})
	}
	devices, err := bindDevices(ctx, segments, rows)
	if err != nil {
		return nil, err
	}
	if err := validateSelectedDevices(selection.SelectedDevices, devices); err != nil {
		return nil, err
	}
	return devices, nil
}
