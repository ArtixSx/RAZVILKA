package physicalscope

import (
	"encoding/binary"
	"slices"
	"testing"
)

func frame(m message) []byte {
	n := 16 + len(m.data)
	raw := make([]byte, (n+3)&^3)
	binary.NativeEndian.PutUint32(raw[:4], uint32(n))
	binary.NativeEndian.PutUint16(raw[4:6], m.kind)
	binary.NativeEndian.PutUint16(raw[6:8], m.flags)
	binary.NativeEndian.PutUint32(raw[8:12], m.seq)
	binary.NativeEndian.PutUint32(raw[12:16], m.pid)
	copy(raw[16:], m.data)
	return raw
}
func TestPhysicalLifecycleRejectsRestoredTupleAndMemberChange(t *testing.T) {
	segments := []Segment{{Interface: "Home", IfIndex: 9, Members: []Link{{Interface: "eth0", IfIndex: 4}}}}
	unrelated := linkFrame(20, "rztun0", "tun", "", 0)
	unrelated.seq, unrelated.pid = 12, 23
	if err := checkNotifications([]message{unrelated}, segments, nil); err != nil {
		t.Fatal("unrelated TUN invalidated physical LAN")
	}
	selected := linkFrame(9, "Home", "bridge", "02:00:00:00:00:01", 0)
	deleted := selected
	deleted.kind = 17
	for name, events := range map[string][]message{
		"identical NEWLINK":          {selected},
		"delete recreated identical": {deleted, selected},
		"member delete":              {linkFrame(4, "eth0", "", "02:00:00:00:00:02", 0)},
		"new member":                 {linkFrame(21, "eth2", "", "02:00:00:00:00:05", 9)},
		"same name other index":      {linkFrame(22, "Home", "bridge", "02:00:00:00:00:01", 0)},
		"address":                    {addressFrame(9, "192.0.2.1/24")},
		"neighbor":                   {neighborFrame(9, "192.0.2.20", "02:00:00:00:00:03", 2)},
		"overrun":                    {{kind: 4}},
		"solicited dump mix":         {{kind: 16, flags: 2, seq: 1, data: selected.data}},
		"selected writer context":    {{kind: 16, pid: 23, seq: 12, data: selected.data}},
		"truncated message":          {{kind: 16, data: []byte{0}}},
	} {
		t.Run(name, func(t *testing.T) {
			if checkNotifications(events, segments, nil) == nil {
				t.Fatal("continuity survived changed/unknown stream")
			}
		})
	}
}
func TestPhysicalWireBoundsAndDuplicates(t *testing.T) {
	m := linkFrame(9, "Home", "bridge", "02:00:00:00:00:01", 0)
	raw := frame(m)
	decoded, err := messages(raw)
	if err != nil || len(decoded) != 1 {
		t.Fatal(err)
	}
	link, err := decodeLink(decoded[0])
	if err != nil || link.kind != "bridge" || link.IfIndex != 9 {
		t.Fatal("bounded link ABI lost")
	}
	for name, mutate := range map[string]func([]byte) []byte{
		"short":               func(b []byte) []byte { return b[:15] },
		"length under header": func(b []byte) []byte { binary.NativeEndian.PutUint32(b[:4], 15); return b },
		"oversize":            func(b []byte) []byte { binary.NativeEndian.PutUint32(b[:4], uint32(len(b)+4)); return b },
		"trailing byte":       func(b []byte) []byte { return append(b, 0) },
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := messages(mutate(slices.Clone(raw))); err == nil {
				t.Fatal("bad framing accepted")
			}
		})
	}
	m.data = append(m.data, attr(3, []byte("other\x00"))...)
	if _, err := decodeLink(m); err == nil {
		t.Fatal("duplicate name attr accepted")
	}
	a := addressFrame(9, "2001:db8::1/64")
	a.data[2] = 0x40
	if _, _, _, err := decodeAddress(a); err == nil {
		t.Fatal("tentative IPv6 accepted")
	}
	a = addressFrame(9, "192.0.2.1/24")
	a.data = append(a.data, attr(2, []byte{192, 0, 2, 2})...)
	if _, _, _, err := decodeAddress(a); err == nil {
		t.Fatal("point-to-point address on LAN accepted")
	}
	n := neighborFrame(9, "192.0.2.20", "02:00:00:00:00:03", 2|4)
	if _, _, err := decodeNeighbor(n); err == nil {
		t.Fatal("mixed neighbor state accepted")
	}
	n = neighborFrame(9, "192.0.2.20", "", 32)
	if _, _, err := decodeNeighbor(n); err != nil {
		t.Fatal("failed row cannot be bounded and ignored", err)
	}
	r := routeFrame(5)
	r.data = append(r.data, attr(9, make([]byte, 8))...)
	if _, err := decodeWAN(r); err == nil {
		t.Fatal("unknown multipath WAN accepted")
	}
}
