package systemprobe

import (
	"encoding/binary"
	"testing"
)

func epochTestU32(order binary.ByteOrder, value uint32) []byte {
	result := make([]byte, 4)
	order.PutUint32(result, value)
	return result
}
func epochTestAttr(order binary.ByteOrder, kind uint16, value []byte) []byte {
	size := len(value) + 4
	result := make([]byte, (size+3)&^3)
	order.PutUint16(result[:2], uint16(size))
	order.PutUint16(result[2:4], kind)
	copy(result[4:], value)
	return result
}
func epochTestLink(order binary.ByteOrder) epochMessage {
	data := make([]byte, 16)
	order.PutUint16(data[2:4], 1)
	order.PutUint32(data[4:8], 4)
	order.PutUint32(data[8:12], 0x10041)
	for _, attribute := range [][]byte{epochTestAttr(order, 3, []byte("eth3\x00")), epochTestAttr(order, 4, epochTestU32(order, 1500)), epochTestAttr(order, 16, []byte{6}), epochTestAttr(order, 33, []byte{1}), epochTestAttr(order, 35, epochTestU32(order, 2))} {
		data = append(data, attribute...)
	}
	return epochMessage{kind: 16, data: data}
}
func epochTestRoute(order binary.ByteOrder, source byte) epochMessage {
	data := make([]byte, 12)
	data[0], data[4], data[5], data[7] = 2, 254, 3, 1
	for _, attribute := range [][]byte{epochTestAttr(order, 4, epochTestU32(order, 4)), epochTestAttr(order, 5, []byte{100, 64, 128, 1}), epochTestAttr(order, 7, []byte{100, 64, 128, source}), epochTestAttr(order, 6, epochTestU32(order, 1000))} {
		data = append(data, attribute...)
	}
	return epochMessage{kind: 24, data: data}
}

func TestEpochWireSupportsLittleAndBigEndianWithoutPrivateDTOs(t *testing.T) {
	for name, order := range map[string]binary.ByteOrder{"little": binary.LittleEndian, "big-mips": binary.BigEndian} {
		t.Run(name, func(t *testing.T) {
			link, err := decodeEpochLink(epochTestLink(order), order)
			if err != nil || link.name != "eth3" || link.index != 4 || !link.up {
				t.Fatalf("link decode: %+v %v", link, err)
			}
			first, err := decodeEpochRoute(epochTestRoute(order, 2), order)
			if err != nil || first.table != 254 || first.metric != 1000 || len(first.interfaces) != 1 || first.interfaces[0] != 4 {
				t.Fatal("default route decode failed")
			}
			second, err := decodeEpochRoute(epochTestRoute(order, 3), order)
			if err != nil || first.canonical == second.canonical {
				t.Fatal("source ignored when gateway exists")
			}
			candidate := epochTestRoute(order, 2)
			candidate.data[4] = 219
			if route, err := decodeEpochRoute(candidate, order); err != nil || route.canonical != "" {
				t.Fatal("candidate table included in underlay")
			}
			service := epochTestRoute(order, 2)
			service.data[1] = 32
			if route, err := decodeEpochRoute(service, order); err != nil || route.canonical != "" {
				t.Fatal("service route included in underlay defaults")
			}
			changed := epochTestLink(order)
			changed.data = append(changed.data, epochTestAttr(order, 7, make([]byte, 64))...)
			other, err := decodeEpochLink(changed, order)
			if err != nil || other.canonical != link.canonical {
				t.Fatal("traffic stats changed link identity")
			}
		})
	}
}

func TestEpochWireAddressIgnoresLifetimeCountdown(t *testing.T) {
	for _, order := range []binary.ByteOrder{binary.LittleEndian, binary.BigEndian} {
		data := make([]byte, 8)
		data[0], data[1] = 10, 64
		order.PutUint32(data[4:8], 4)
		data = append(data, epochTestAttr(order, 1, []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1})...)
		first := epochMessage{kind: 20, data: append(append([]byte{}, data...), epochTestAttr(order, 6, make([]byte, 16))...)}
		_, a, err := decodeEpochAddress(first, order)
		if err != nil {
			t.Fatal(err)
		}
		second := epochMessage{kind: 20, data: append(append([]byte{}, data...), epochTestAttr(order, 6, []byte{0, 0, 0, 9, 0, 0, 0, 8, 0, 0, 0, 0, 0, 0, 0, 0})...)}
		_, b, err := decodeEpochAddress(second, order)
		if err != nil || a != b {
			t.Fatal("address lifetime countdown changed identity")
		}
		second.data[2] = 0x20 // DEPRECATED is a meaningful state transition
		_, b, err = decodeEpochAddress(second, order)
		if err != nil || a == b {
			t.Fatal("address deprecation was ignored")
		}
	}
}

func TestEpochWireRejectsTruncatedAndMalformedInput(t *testing.T) {
	for _, order := range []binary.ByteOrder{binary.LittleEndian, binary.BigEndian} {
		for _, raw := range [][]byte{{1}, make([]byte, 16), append(epochTestU32(order, 0xffffffff), make([]byte, 12)...)} {
			if _, err := epochMessages(raw, order); err == nil {
				t.Fatal("malformed netlink frame accepted")
			}
		}
		for _, raw := range [][]byte{{1}, []byte{0, 0, 0, 0}, append(epochTestAttr(order, 1, []byte{1}), epochTestAttr(order, 1, []byte{2})...)} {
			if _, err := epochAttrs(raw, order); err == nil {
				t.Fatal("malformed attributes accepted")
			}
		}
	}
}

func FuzzEpochNetlinkBounds(f *testing.F) {
	f.Add([]byte{})
	f.Add(epochTestRoute(binary.LittleEndian, 2).data)
	f.Add(epochTestLink(binary.BigEndian).data)
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 4096 {
			return
		}
		for _, order := range []binary.ByteOrder{binary.LittleEndian, binary.BigEndian} {
			_, _ = epochMessages(raw, order)
			_, _ = epochAttrs(raw, order)
			message := epochMessage{data: raw}
			_, _ = decodeEpochLink(message, order)
			_, _ = decodeEpochRoute(message, order)
			_, _, _ = decodeEpochAddress(message, order)
		}
	})
}
