package systemprobe

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"sort"
	"strings"
)

// Small, bounds-checked rtnetlink decoder shared with platform-independent
// fixtures. Wire integers use the host's byte order, including big-endian MIPS.
type epochMessage struct {
	kind, flags uint16
	seq, pid    uint32
	data        []byte
}

func epochMessages(data []byte, order binary.ByteOrder) ([]epochMessage, error) {
	var result []epochMessage
	for len(data) > 0 {
		if len(data) < 16 {
			return nil, ErrNetworkUnavailable
		}
		size := uint64(order.Uint32(data[:4]))
		aligned := (size + 3) &^ 3
		if size < 16 || aligned > uint64(len(data)) {
			return nil, ErrNetworkUnavailable
		}
		result = append(result, epochMessage{kind: order.Uint16(data[4:6]), flags: order.Uint16(data[6:8]), seq: order.Uint32(data[8:12]), pid: order.Uint32(data[12:16]), data: data[16:size]})
		if len(result) > 8192 {
			return nil, ErrNetworkUnavailable
		}
		data = data[aligned:]
	}
	return result, nil
}

func epochAttrs(data []byte, order binary.ByteOrder) (map[uint16][]byte, error) {
	attrs := map[uint16][]byte{}
	for len(data) > 0 {
		if len(data) < 4 {
			return nil, ErrNetworkUnavailable
		}
		size := int(order.Uint16(data[:2]))
		aligned := (size + 3) &^ 3
		kind := order.Uint16(data[2:4]) & 0x3fff
		if size < 4 || aligned > len(data) || len(attrs) >= 256 {
			return nil, ErrNetworkUnavailable
		}
		if _, exists := attrs[kind]; exists {
			return nil, ErrNetworkUnavailable
		}
		attrs[kind] = data[4:size]
		data = data[aligned:]
	}
	return attrs, nil
}

func epochU32(attrs map[uint16][]byte, key uint16, order binary.ByteOrder) (uint32, error) {
	value, exists := attrs[key]
	if !exists {
		return 0, nil
	}
	if len(value) != 4 {
		return 0, ErrNetworkUnavailable
	}
	return order.Uint32(value), nil
}

func epochIP(raw []byte, family byte) (string, error) {
	if len(raw) == 0 {
		return "", nil
	}
	if family != 2 && family != 10 || family == 2 && len(raw) != 4 || family == 10 && len(raw) != 16 {
		return "", ErrNetworkUnavailable
	}
	address, ok := netip.AddrFromSlice(raw)
	if !ok {
		return "", ErrNetworkUnavailable
	}
	return address.String(), nil
}

type epochLink struct {
	index, parent, master uint32
	name, canonical       string
	up                    bool
}

func decodeEpochLink(message epochMessage, order binary.ByteOrder) (epochLink, error) {
	if len(message.data) < 16 {
		return epochLink{}, ErrNetworkUnavailable
	}
	d := message.data
	attrs, err := epochAttrs(d[16:], order)
	if err != nil {
		return epochLink{}, err
	}
	link := epochLink{index: order.Uint32(d[4:8])}
	name := attrs[3]
	if len(name) < 2 || len(name) > 16 || name[len(name)-1] != 0 || strings.ContainsAny(string(name[:len(name)-1]), "/\x00\n\r") {
		return epochLink{}, ErrNetworkUnavailable
	}
	link.name = string(name[:len(name)-1])
	mtu, err := epochU32(attrs, 4, order)
	if err != nil {
		return epochLink{}, err
	}
	link.parent, err = epochU32(attrs, 5, order)
	if err != nil {
		return epochLink{}, err
	}
	link.master, err = epochU32(attrs, 10, order)
	if err != nil {
		return epochLink{}, err
	}
	flags := order.Uint32(d[8:12]) & (1 | 0x40 | 0x10000 | 0x20000) // UP/RUNNING/LOWER_UP/DORMANT
	link.up = flags&1 != 0 && flags&0x20000 == 0
	state := "missing"
	if value, exists := attrs[16]; exists {
		if len(value) != 1 {
			return epochLink{}, ErrNetworkUnavailable
		}
		state = fmt.Sprint(value[0])
		if value[0] == 2 || value[0] == 3 || value[0] == 5 {
			link.up = false
		}
	}
	carrier := "missing"
	if value, exists := attrs[33]; exists {
		if len(value) != 1 || value[0] > 1 {
			return epochLink{}, ErrNetworkUnavailable
		}
		carrier = fmt.Sprint(value[0])
		if value[0] == 0 {
			link.up = false
		}
	}
	changes := "missing"
	if _, exists := attrs[35]; exists {
		value, err := epochU32(attrs, 35, order)
		if err != nil {
			return epochLink{}, err
		}
		changes = fmt.Sprint(value)
	}
	link.canonical = fmt.Sprintf("link=%d|%s|type=%d|parent=%d|master=%d|mtu=%d|flags=%d|state=%s|carrier=%s|changes=%s", link.index, link.name, order.Uint16(d[2:4]), link.parent, link.master, mtu, flags, state, carrier, changes)
	if link.index == 0 {
		return epochLink{}, ErrNetworkUnavailable
	}
	return link, nil
}

type epochRoute struct {
	family       byte
	table        uint32
	metric       uint32
	defaultRoute bool
	universe     bool
	interfaces   []uint32
	canonical    string
}

func decodeEpochRoute(message epochMessage, order binary.ByteOrder) (epochRoute, error) {
	if len(message.data) < 12 {
		return epochRoute{}, ErrNetworkUnavailable
	}
	d := message.data
	attrs, err := epochAttrs(d[12:], order)
	if err != nil {
		return epochRoute{}, err
	}
	route := epochRoute{family: d[0], table: uint32(d[4]), defaultRoute: d[1] == 0, universe: d[6] == 0}
	if _, exists := attrs[15]; exists {
		route.table, err = epochU32(attrs, 15, order)
		if err != nil {
			return epochRoute{}, err
		}
	}
	if route.table != 254 || d[0] != 2 && d[0] != 10 {
		return route, nil
	}
	if !route.defaultRoute {
		return route, nil
	}
	if d[7] != 1 || d[2] != 0 || order.Uint32(d[8:12])&0x200 != 0 {
		return route, ErrNetworkUnavailable
	}
	iface, err := epochU32(attrs, 4, order)
	if err != nil {
		return route, err
	}
	if iface != 0 {
		route.interfaces = append(route.interfaces, iface)
	}
	metric, err := epochU32(attrs, 6, order)
	if err != nil {
		return route, err
	}
	route.metric = metric
	via, err := epochIP(attrs[5], d[0])
	if err != nil {
		return route, err
	}
	src, err := epochIP(attrs[7], d[0])
	if err != nil {
		return route, err
	}
	var nexthops []string
	for value := attrs[9]; len(value) > 0; {
		if len(value) < 8 {
			return route, ErrNetworkUnavailable
		}
		size := int(order.Uint16(value[:2]))
		aligned := (size + 3) &^ 3
		if size < 8 || aligned > len(value) || len(nexthops) >= 32 {
			return route, ErrNetworkUnavailable
		}
		nextIndex := order.Uint32(value[4:8])
		if nextIndex == 0 {
			return route, ErrNetworkUnavailable
		}
		nextAttrs, err := epochAttrs(value[8:size], order)
		if err != nil {
			return route, err
		}
		nextVia, err := epochIP(nextAttrs[5], d[0])
		if err != nil {
			return route, err
		}
		nexthops = append(nexthops, fmt.Sprintf("%d|%s|%d|%d", nextIndex, nextVia, value[2], value[3]))
		route.interfaces = append(route.interfaces, nextIndex)
		value = value[aligned:]
	}
	if len(route.interfaces) == 0 {
		return route, ErrNetworkUnavailable
	}
	sort.Strings(nexthops)
	sort.Slice(route.interfaces, func(i, j int) bool { return route.interfaces[i] < route.interfaces[j] })
	route.canonical = fmt.Sprintf("default=%d|table=%d|dev=%d|via=%s|src=%s|metric=%d|protocol=%d|scope=%d|tos=%d|nexthops=%s|pref=%x|metrics=%x", d[0], route.table, iface, via, src, metric, d[5], d[6], d[3], strings.Join(nexthops, ","), attrs[20], attrs[8])
	return route, nil
}

func decodeEpochAddress(message epochMessage, order binary.ByteOrder) (uint32, string, error) {
	if len(message.data) < 8 {
		return 0, "", ErrNetworkUnavailable
	}
	d := message.data
	index := order.Uint32(d[4:8])
	if d[0] != 2 && d[0] != 10 {
		return index, "", nil
	}
	if d[1] > 128 || d[0] == 2 && d[1] > 32 {
		return 0, "", ErrNetworkUnavailable
	}
	attrs, err := epochAttrs(d[8:], order)
	if err != nil {
		return 0, "", err
	}
	address, err := epochIP(attrs[1], d[0])
	if err != nil {
		return 0, "", err
	}
	local, err := epochIP(attrs[2], d[0])
	if err != nil {
		return 0, "", err
	}
	if address == "" && local == "" {
		return 0, "", ErrNetworkUnavailable
	}
	flags := uint32(d[2])
	if _, exists := attrs[8]; exists {
		flags, err = epochU32(attrs, 8, order)
		if err != nil {
			return 0, "", err
		}
	}
	return index, fmt.Sprintf("addr=%d|dev=%d|%s|local=%s|prefix=%d|scope=%d|flags=%d", d[0], index, address, local, d[1], d[3], flags), nil
}
