package physicalscope

import (
	"context"
	"encoding/binary"
	"reflect"
	"slices"
	"strconv"
	"testing"
)

func wirelessMember() Link {
	return Link{Interface: "radio-a", IfIndex: 13, MAC: "02:00:00:00:00:03", NativeID: "Wifi0/AP0", NativeType: "AccessPoint", Origin: "ndm", LinkType: 1, Flags: 69699, MasterIfIndex: 9}
}

func wirelessFrame(member Link, payload []byte) message {
	raw := make([]byte, 16)
	binary.NativeEndian.PutUint16(raw[2:4], member.LinkType)
	binary.NativeEndian.PutUint32(raw[4:8], uint32(member.IfIndex))
	binary.NativeEndian.PutUint32(raw[8:12], member.Flags)
	raw = append(raw, attr(3, append([]byte(member.Interface), 0))...)
	raw = append(raw, attr(11, payload)...)
	return message{kind: 16, data: raw}
}

func wirelessCustom(payload []byte) []byte {
	const word = strconv.IntSize / 8
	raw := make([]byte, 2*word+len(payload))
	binary.NativeEndian.PutUint16(raw[:2], uint16(len(raw)))
	binary.NativeEndian.PutUint16(raw[2:4], 0x8c02)
	binary.NativeEndian.PutUint16(raw[word:word+2], uint16(len(payload)))
	copy(raw[2*word:], payload)
	return raw
}

func wirelessSegments() []Segment {
	return []Segment{{ID: "Bridge0", Interface: "Home", IfIndex: 9, Members: []Link{wirelessMember()}}}
}

func TestPhysicalWirelessPartialNotificationDoesNotAssertZeroTopology(t *testing.T) {
	segments := wirelessSegments()
	original := cloneSnapshot(Snapshot{Segments: segments})
	for _, size := range []int{0, 112, 256} {
		payload := wirelessCustom(make([]byte, size))
		// Driver flags and tail padding are opaque iw_point metadata, as in the
		// kernel memcpy from iwreq_data. They cannot change any frozen binding.
		const word = strconv.IntSize / 8
		binary.NativeEndian.PutUint16(payload[word+2:word+4], 0x1234)
		for i := word + 4; i < 2*word; i++ {
			payload[i] = 0xa5
		}
		event := wirelessFrame(segments[0].Members[0], payload)
		partial, err := decodeLink(event)
		if err != nil || partial.MAC != "" || partial.MasterIfIndex != 0 {
			t.Fatal("fixture no longer represents a partial wireless notification")
		}
		if err := checkNotifications([]message{event, event}, segments, nil); err != nil {
			t.Fatal("original AP's partial WEXT became a zero/changed link", err)
		}
		if !reflect.DeepEqual(Snapshot{Segments: segments}, original) {
			t.Fatal("advisory WEXT replaced original full topology")
		}
	}
}

func TestPhysicalWirelessRefusesChangedBindingHeaderRoleAndExtraAttributes(t *testing.T) {
	for _, variant := range []string{"name", "index", "negative-index", "flags", "netlink-flags", "seq", "pid", "family", "pad", "link-type", "change-mask", "delete", "master", "mac", "link-info", "unknown-attribute", "duplicate-name", "duplicate-wireless", "nested-name", "malformed-attribute", "missing-name", "missing-wireless", "origin", "native-type", "native-id", "member-kind", "member-link-type", "member-master", "vlan", "foreign-parent", "down", "first-role", "ambiguous", "root", "parent"} {
		t.Run(variant, func(t *testing.T) {
			segments := wirelessSegments()
			member := segments[0].Members[0]
			event := wirelessFrame(member, wirelessCustom(make([]byte, 112)))
			switch variant {
			case "name":
				member.Interface = "changed-name"
				event = wirelessFrame(member, wirelessCustom(nil))
			case "index":
				binary.NativeEndian.PutUint32(event.data[4:8], 14)
			case "negative-index":
				binary.NativeEndian.PutUint32(event.data[4:8], ^uint32(0))
			case "flags":
				binary.NativeEndian.PutUint32(event.data[8:12], member.Flags^0x10000)
			case "netlink-flags":
				event.flags = 2
			case "seq":
				event.seq = 1
			case "pid":
				event.pid = 1
			case "family":
				event.data[0] = 7
			case "pad":
				event.data[1] = 1
			case "link-type":
				binary.NativeEndian.PutUint16(event.data[2:4], 772)
			case "change-mask":
				binary.NativeEndian.PutUint32(event.data[12:16], 1)
			case "delete":
				event.kind = 17
			case "master":
				event.data = append(event.data, attr(10, integer(9))...)
			case "mac":
				event.data = append(event.data, attr(1, []byte{2, 0, 0, 0, 0, 3})...)
			case "link-info":
				event.data = append(event.data, attr(18, attr(4, []byte("bridge\x00")))...)
			case "unknown-attribute":
				event.data = append(event.data, attr(250, nil)...)
			case "duplicate-name":
				event.data = append(event.data, attr(3, []byte("radio-a\x00"))...)
			case "duplicate-wireless":
				event.data = append(event.data, attr(11, wirelessCustom(nil))...)
			case "nested-name":
				binary.NativeEndian.PutUint16(event.data[18:20], 0x8000|3)
			case "malformed-attribute":
				event.data = event.data[:len(event.data)-1]
			case "missing-name":
				event.data = append(slices.Clone(event.data[:16]), attr(11, wirelessCustom(nil))...)
			case "missing-wireless":
				event.data = append(slices.Clone(event.data[:16]), attr(3, []byte("radio-a\x00"))...)
			case "origin":
				segments[0].Members[0].Origin = "kernel"
			case "native-type":
				segments[0].Members[0].NativeType = "Port"
			case "native-id":
				segments[0].Members[0].NativeID = ""
			case "member-kind":
				segments[0].Members[0].Kind = "vlan"
			case "member-link-type":
				segments[0].Members[0].LinkType = 772
			case "first-role":
				segments[0].Members[0].Origin, segments[0].Members[0].NativeType = "kernel", "Port"
			case "member-master":
				segments[0].Members[0].MasterIfIndex = 10
			case "vlan":
				segments[0].Members[0].VLAN.Known = true
			case "foreign-parent":
				segments[0].Members[0].ForeignParent = true
			case "down":
				segments[0].Members[0].Flags &^= 1
				event = wirelessFrame(segments[0].Members[0], wirelessCustom(nil))
			case "ambiguous":
				segments[0].Members = append(segments[0].Members, member)
			case "root":
				member.Interface, member.IfIndex = "Home", 9
				event = wirelessFrame(member, wirelessCustom(nil))
			case "parent":
				segments[0].Members[0].Parent = ParentLink{Known: true, Interface: "radio-parent", IfIndex: 21}
				member.Interface, member.IfIndex = "radio-parent", 21
				event = wirelessFrame(member, wirelessCustom(nil))
			}
			err := checkNotifications([]message{event}, segments, nil)
			if err == nil {
				t.Fatal("unproved partial LINK was waived", variant)
			}
			reason := map[string]string{"origin": "origin", "native-type": "native-type", "native-id": "native-id", "member-kind": "kind", "member-link-type": "link-type", "member-master": "master", "vlan": "vlan", "foreign-parent": "foreign-parent", "down": "flags", "first-role": "origin"}[variant]
			if reason != "" && !slices.Equal(DiagnosticStages(err), []string{"notifications.wireless.role", "notifications.wireless.role." + reason}) {
				t.Fatal("original role refusal lost its first closed reason")
			}
		})
	}
}

func TestPhysicalWirelessCustomRequiresOneBoundedNativeEvent(t *testing.T) {
	const word = strconv.IntSize / 8
	for _, variant := range []string{"empty", "short", "oversize", "event-length", "tokens", "unknown-command", "association", "expiry", "setter", "packed-abi", "concatenated", "header-padding"} {
		t.Run(variant, func(t *testing.T) {
			raw := wirelessCustom(make([]byte, 112))
			switch variant {
			case "empty":
				raw = nil
			case "short":
				raw = raw[:2*word-1]
			case "oversize":
				raw = wirelessCustom(make([]byte, 257))
			case "event-length":
				binary.NativeEndian.PutUint16(raw[:2], uint16(len(raw)-1))
			case "tokens":
				binary.NativeEndian.PutUint16(raw[word:word+2], 111)
			case "unknown-command":
				binary.NativeEndian.PutUint16(raw[2:4], 0xffff)
			case "association":
				binary.NativeEndian.PutUint16(raw[2:4], 0x8c03)
			case "expiry":
				binary.NativeEndian.PutUint16(raw[2:4], 0x8c04)
			case "setter":
				binary.NativeEndian.PutUint16(raw[2:4], 0x8b06)
			case "packed-abi":
				if word == 4 {
					t.Skip("packed and native point layout coincide on this ABI")
				}
				raw = append(slices.Clone(raw[:4]), raw[word:word+4]...)
				binary.NativeEndian.PutUint16(raw[:2], uint16(len(raw)))
			case "concatenated":
				raw = append(wirelessCustom(nil), wirelessCustom(nil)...)
			case "header-padding":
				if word == 4 {
					t.Skip("no LCP padding on native 32-bit")
				}
				raw[4] = 1
			}
			if err := checkNotifications([]message{wirelessFrame(wirelessMember(), raw)}, wirelessSegments(), nil); err == nil {
				t.Fatal("unrecognized WEXT payload became an advisory exemption", variant)
			}
		})
	}
}

func TestPhysicalWirelessCannotHideRealTopologyChangesOrReviveReview(t *testing.T) {
	for _, variant := range []string{"full-link", "delete-restore", "flags-restore", "prefix-restore", "binding-restore"} {
		t.Run(variant, func(t *testing.T) {
			o, m, ctx := newModel(t)
			m.facts.Segments[0].Members = []Link{wirelessMember()}
			f := &packetFence{}
			o.source.open = func(context.Context) (lifecycleFence, error) { m.fence.opened = true; return f, nil }
			wireless := wirelessFrame(wirelessMember(), wirelessCustom(make([]byte, 112)))
			f.events = []message{wireless}
			r, err := o.Observe(ctx)
			if err != nil {
				t.Fatal("actual-shaped advisory prevented initial review", err)
			}
			defer r.Close()
			original := r.Snapshot()
			f.events = []message{wireless}
			if err := o.Verify(ctx, r); err != nil || m.captures != 4 || !reflect.DeepEqual(original, r.Snapshot()) {
				t.Fatal("wireless bypassed fresh captures or refreshed original facts", err)
			}
			saved := cloneSnapshot(m.facts)
			full := linkFrame(13, "radio-a", "", wirelessMember().MAC, 9)
			binary.NativeEndian.PutUint32(full.data[8:12], wirelessMember().Flags)
			f.events = []message{wireless}
			switch variant {
			case "full-link":
				f.events = append(f.events, full)
			case "delete-restore":
				deleted := full
				deleted.kind = 17
				f.events = append(f.events, deleted, full, wireless)
			case "flags-restore":
				changed := wireless
				changed.data = slices.Clone(wireless.data)
				binary.NativeEndian.PutUint32(changed.data[8:12], wirelessMember().Flags^1)
				f.events = append(f.events, changed, wireless)
			case "prefix-restore":
				m.facts.Segments[0].Prefixes[0] = "192.0.3.0/24"
			case "binding-restore":
				m.facts.Devices[0].MAC = "02:00:00:00:00:09"
			}
			if err := o.Verify(ctx, r); err == nil {
				t.Fatal("advisory erased real interface/client/topology mutation", variant)
			}
			m.facts, f.events = saved, []message{wireless}
			if err := o.Verify(ctx, r); err == nil {
				t.Fatal("restored interface plus WEXT revived the original Review", variant)
			}
		})
	}
}
