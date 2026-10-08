package physicalscope

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"net"
	"net/netip"
	"sort"
	"strings"
)

type message struct {
	kind, flags uint16
	seq, pid    uint32
	data        []byte
}

func messages(raw []byte) ([]message, error) {
	var out []message
	for len(raw) > 0 {
		if len(raw) < 16 {
			return nil, ErrUnknown
		}
		n := uint64(binary.NativeEndian.Uint32(raw[:4]))
		aligned := (n + 3) &^ 3
		if n < 16 || aligned > uint64(len(raw)) || len(out) >= 8192 {
			return nil, ErrUnknown
		}
		out = append(out, message{binary.NativeEndian.Uint16(raw[4:6]), binary.NativeEndian.Uint16(raw[6:8]), binary.NativeEndian.Uint32(raw[8:12]), binary.NativeEndian.Uint32(raw[12:16]), raw[16:n]})
		raw = raw[aligned:]
	}
	if len(out) == 0 {
		return nil, ErrUnknown
	}
	return out, nil
}
func attrs(raw []byte) (map[uint16][]byte, error) {
	out := map[uint16][]byte{}
	for len(raw) > 0 {
		if len(raw) < 4 {
			return nil, ErrUnknown
		}
		n := int(binary.NativeEndian.Uint16(raw[:2]))
		aligned := (n + 3) &^ 3
		rawKind := binary.NativeEndian.Uint16(raw[2:4])
		if rawKind&0x4000 != 0 {
			return nil, ErrUnknown
		}
		kind := rawKind & 0x3fff
		if n < 4 || aligned > len(raw) || len(out) >= 256 {
			return nil, ErrUnknown
		}
		if _, exists := out[kind]; exists {
			return nil, ErrUnknown
		}
		out[kind] = raw[4:n]
		raw = raw[aligned:]
	}
	return out, nil
}
func u32(a map[uint16][]byte, kind uint16) (uint32, error) {
	if a[kind] == nil {
		return 0, nil
	}
	if len(a[kind]) != 4 {
		return 0, ErrUnknown
	}
	return binary.NativeEndian.Uint32(a[kind]), nil
}
func wireString(raw []byte, max int) (string, error) {
	if len(raw) < 2 || len(raw) > max+1 || raw[len(raw)-1] != 0 || strings.ContainsAny(string(raw[:len(raw)-1]), "\x00\n\r") {
		return "", ErrUnknown
	}
	return string(raw[:len(raw)-1]), nil
}

type kernelLink struct {
	Link
	master   int
	kind     string
	linkType uint16
	up       bool
}

func decodeLink(m message) (kernelLink, error) {
	if len(m.data) < 16 {
		return kernelLink{}, ErrUnknown
	}
	a, err := attrs(m.data[16:])
	if err != nil {
		return kernelLink{}, err
	}
	name, err := wireString(a[3], 15)
	index := int(int32(binary.NativeEndian.Uint32(m.data[4:8])))
	if err != nil || !interfaceName.MatchString(name) || index <= 0 {
		return kernelLink{}, ErrUnknown
	}
	master, err := u32(a, 10)
	if err != nil {
		return kernelLink{}, err
	}
	parent, err := u32(a, 5)
	if err != nil || int32(parent) < 0 || int32(master) < 0 || a[37] != nil && len(a[37]) != 4 {
		return kernelLink{}, ErrUnknown
	}
	linkType := binary.NativeEndian.Uint16(m.data[2:4])
	flags := binary.NativeEndian.Uint32(m.data[8:12])
	result := kernelLink{Link: Link{Interface: name, IfIndex: index, MAC: net.HardwareAddr(a[1]).String(), LinkType: linkType, Flags: flags, MasterIfIndex: int(master), ParentIfIndex: int(parent), ForeignParent: a[37] != nil}, linkType: linkType, master: int(master), up: flags&1 != 0}
	if info := a[18]; info != nil {
		nested, err := attrs(info)
		if err != nil {
			return kernelLink{}, err
		}
		if nested[1] != nil {
			result.kind, err = wireString(nested[1], 64)
			if err != nil {
				return kernelLink{}, err
			}
		}
		if result.kind == "vlan" {
			result.VLAN, err = decodeVLAN(nested[2])
			if err != nil {
				return kernelLink{}, err
			}
		}
		if nested[4] != nil {
			result.SlaveKind, err = wireString(nested[4], 64)
			if err != nil {
				return kernelLink{}, err
			}
		}
		if result.SlaveKind == "bridge" && nested[5] != nil {
			port, err := attrs(nested[5])
			if err != nil || port[1] != nil && (len(port[1]) != 1 || port[1][0] > 4) {
				return kernelLink{}, ErrUnknown
			}
			if port[1] != nil {
				result.BridgeStateKnown, result.BridgePortState = true, port[1][0]
			}
		}
	}
	result.Link.Kind = result.kind
	return result, nil
}

func decodeVLAN(raw []byte) (VLANFacts, error) {
	a, err := attrs(raw)
	if err != nil || len(a[1]) != 2 || len(a[5]) != 2 {
		return VLANFacts{}, ErrUnknown
	}
	v := VLANFacts{Known: true, ID: binary.NativeEndian.Uint16(a[1]), Protocol: binary.BigEndian.Uint16(a[5])}
	if v.ID > 4094 {
		return VLANFacts{}, ErrUnknown
	}
	if a[2] != nil {
		if len(a[2]) != 8 {
			return VLANFacts{}, ErrUnknown
		}
		v.FlagsKnown, v.Flags, v.FlagsMask = true, binary.NativeEndian.Uint32(a[2][:4]), binary.NativeEndian.Uint32(a[2][4:])
	}
	for key, value := range a {
		if key != 1 && key != 2 && key != 5 && (key != 3 && key != 4 || len(value) != 0) {
			v.Unsupported = true
		}
	}
	// Bind the exact bounded configuration bytes as well as decoded fields.
	// This is attribute evidence, not an interface incarnation or authority.
	digest := sha256.Sum256(raw)
	v.InfoSHA256 = hex.EncodeToString(digest[:])
	return v, nil
}
func decodeAddress(m message) (int, string, string, error) {
	if len(m.data) < 8 || m.data[0] != 2 && m.data[0] != 10 {
		return 0, "", "", ErrUnknown
	}
	a, err := attrs(m.data[8:])
	if err != nil {
		return 0, "", "", err
	}
	flags := uint32(m.data[2])
	if a[8] != nil {
		flags, err = u32(a, 8)
		if err != nil {
			return 0, "", "", err
		}
	}
	// Tentative/DAD-failed addresses cannot supply a usable LAN prefix.
	if flags&(0x08|0x40) != 0 {
		return 0, "", "", ErrUnknown
	}
	raw := a[2]
	if raw == nil {
		raw = a[1]
	}
	if a[1] != nil && a[2] != nil && !bytes.Equal(a[1], a[2]) {
		return 0, "", "", ErrUnknown
	}
	address, ok := netip.AddrFromSlice(raw)
	if !ok || address.Is4In6() || address.Is4() != (m.data[0] == 2) || address.IsUnspecified() || address.IsMulticast() || address.IsLoopback() {
		return 0, "", "", ErrUnknown
	}
	bits := int(m.data[1])
	if bits <= 0 || bits > address.BitLen() {
		return 0, "", "", ErrUnknown
	}
	index := int(binary.NativeEndian.Uint32(m.data[4:8]))
	if index <= 0 {
		return 0, "", "", ErrUnknown
	}
	p := netip.PrefixFrom(address, bits)
	prefix := ""
	if lanPrefix(p.Masked()) {
		prefix = p.Masked().String()
	}
	return index, p.String(), prefix, nil
}
func decodeNeighbor(m message) (int, string, error) {
	n, err := parseKernelNeighbor(m)
	if err != nil {
		return 0, "", err
	}
	if err := validateUnicastNeighbor(n); err != nil {
		return 0, "", err
	}
	// The legacy textual row has no flags/role slot. Never erase a router bit
	// into that client representation; the actual capture uses the typed path.
	if n.flags&128 != 0 {
		return 0, "", at("kernel.bindings.neighbor.router-role", nil)
	}
	return n.index, n.row(), nil
}
func decodeWAN(m message) ([]int, error) {
	if len(m.data) < 12 || m.data[0] != 2 && m.data[0] != 10 {
		return nil, ErrUnknown
	}
	d := m.data
	a, err := attrs(d[12:])
	if err != nil {
		return nil, err
	}
	table := uint32(d[4])
	if a[15] != nil {
		table, err = u32(a, 15)
		if err != nil {
			return nil, err
		}
	}
	if d[1] != 0 || table != 254 || d[7] != 1 {
		return nil, nil
	}
	if a[9] != nil {
		return nil, ErrUnknown
	} // Unknown multipath WAN refuses.
	index, err := u32(a, 4)
	if err != nil || index == 0 {
		return nil, ErrUnknown
	}
	return []int{int(index)}, nil
}
func uniqueSorted(values []string) ([]string, error) {
	sort.Strings(values)
	for i := 1; i < len(values); i++ {
		if values[i] == values[i-1] {
			return nil, ErrUnknown
		}
	}
	return values, nil
}

func checkNotifications(frames []message, segments []Segment, devices []Device) error {
	tracked, roots, names := map[int]bool{}, map[int]bool{}, map[string]bool{}
	byIndex := map[int]Segment{}
	routerMACs := map[string]bool{}
	for _, s := range segments {
		byIndex[s.IfIndex] = s
		for _, n := range s.RouterNeighbors {
			if n.Flags&128 != 0 {
				routerMACs[n.MAC] = true
			}
		}
		tracked[s.IfIndex], roots[s.IfIndex], names[s.Interface] = true, true, true
		for _, m := range s.Members {
			tracked[m.IfIndex], names[m.Interface] = true, true
			if m.Parent.Known {
				tracked[m.Parent.IfIndex], names[m.Parent.Interface] = true, true
			}
		}
	}
	for _, m := range frames {
		// receive authenticates the datagram's kernel sender (sockaddr PID0).
		// A multicast notification can retain the triggering writer's header
		// sequence/port ID; those fields do not make it a foreign datagram.
		// This socket issues no requests, so dump/multipart flags still refuse.
		// Route multicast can carry the writer's CREATE/EXCL/REPLACE/APPEND
		// operation flags. They describe the change, not a dump response.
		allowedFlags := uint16(0)
		if m.kind == 24 || m.kind == 25 {
			allowedFlags = 0xf00
		}
		if m.flags&^allowedFlags != 0 {
			return ErrUnknown
		}
		switch m.kind {
		case 16, 17:
			link, err := decodeLink(m)
			if err != nil {
				return err
			}
			if tracked[link.IfIndex] || roots[link.master] || names[link.Interface] || link.ParentIfIndex != 0 && tracked[link.ParentIfIndex] {
				return ErrUnknown
			}
		case 20, 21:
			if len(m.data) < 8 {
				return ErrUnknown
			}
			if tracked[int(binary.NativeEndian.Uint32(m.data[4:8]))] {
				return ErrUnknown
			}
		case 28, 29:
			if len(m.data) < 12 {
				return ErrUnknown
			}
			if segment, selected := byIndex[int(binary.NativeEndian.Uint32(m.data[4:8]))]; selected {
				n, bookkeeping, err := decodeSegmentNeighbor(m, segment)
				if err != nil {
					return err
				}
				if bookkeeping {
					continue
				}
				if m.kind == 29 || n.state == 1 || n.state == 32 || !validMAC(n.mac) {
					return ErrUnknown
				}
				matched := 0
				for _, r := range segment.RouterNeighbors {
					if r.Address == n.address.String() && r.MAC == n.mac && r.Flags == n.flags && r.Type == n.kind {
						matched++
					}
				}
				for _, d := range devices {
					if !routerMACs[n.mac] && n.flags&128 == 0 && d.IfIndex == n.index && d.MAC == n.mac && (slicesContains(d.Addresses, n.address.String()) || slicesContains(d.LinkLocalAddresses, n.address.String())) {
						matched++
					}
				}
				if matched != 1 {
					return ErrUnknown
				}
			}
		case 24, 25:
			indices, err := decodeWAN(m)
			if err != nil {
				return err
			}
			for _, index := range indices {
				if tracked[index] {
					return ErrUnknown
				}
			}
		default:
			return ErrUnknown
		}
	}
	return nil
}
