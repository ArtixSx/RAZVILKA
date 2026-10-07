package physicalscope

import (
	"bytes"
	"encoding/binary"
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
	result := kernelLink{Link: Link{Interface: name, IfIndex: index, MAC: net.HardwareAddr(a[1]).String()}, linkType: binary.NativeEndian.Uint16(m.data[2:4]), master: int(master), up: binary.NativeEndian.Uint32(m.data[8:12])&1 != 0}
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
	}
	result.Link.Kind = result.kind
	return result, nil
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
	if len(m.data) < 12 || m.data[0] != 2 && m.data[0] != 10 {
		return 0, "", ErrUnknown
	}
	a, err := attrs(m.data[12:])
	if err != nil {
		return 0, "", err
	}
	index := int(int32(binary.NativeEndian.Uint32(m.data[4:8])))
	address, ok := netip.AddrFromSlice(a[1])
	if index <= 0 || !ok || address.Is4In6() || address.Is4() != (m.data[0] == 2) || address.IsUnspecified() || address.IsLoopback() || address.IsMulticast() {
		return 0, "", ErrUnknown
	}
	state := binary.NativeEndian.Uint16(m.data[8:10])
	states := map[uint16]string{1: "INCOMPLETE", 2: "REACHABLE", 4: "STALE", 8: "DELAY", 16: "PROBE", 32: "FAILED", 64: "NOARP", 128: "PERMANENT"}
	label := states[state]
	if label == "" || m.data[11] != 1 || m.data[10]&^(byte(2|8|16)) != 0 {
		return 0, "", ErrUnknown
	}
	mac := net.HardwareAddr(a[2]).String()
	if state != 1 && state != 32 && !validMAC(mac) {
		return 0, "", ErrUnknown
	}
	row := address.String()
	if len(a[2]) != 0 {
		row += " lladdr " + mac
	}
	row += " " + label + "\n"
	return index, row, nil
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

func checkNotifications(frames []message, segments []Segment) error {
	tracked, roots, names := map[int]bool{}, map[int]bool{}, map[string]bool{}
	for _, s := range segments {
		tracked[s.IfIndex], roots[s.IfIndex], names[s.Interface] = true, true, true
		for _, m := range s.Members {
			tracked[m.IfIndex], names[m.Interface] = true, true
		}
	}
	for _, m := range frames {
		if m.seq != 0 || m.pid != 0 || m.flags != 0 {
			return ErrUnknown
		}
		switch m.kind {
		case 16, 17:
			link, err := decodeLink(m)
			if err != nil {
				return err
			}
			if tracked[link.IfIndex] || roots[link.master] || names[link.Interface] {
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
			if roots[int(binary.NativeEndian.Uint32(m.data[4:8]))] {
				return ErrUnknown
			}
		default:
			return ErrUnknown
		}
	}
	return nil
}
