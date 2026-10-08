package physicalscope

import (
	"context"
	"encoding/binary"
	"slices"
	"testing"
)

func bookkeepingFrame(address, mac string, kind byte) message {
	m := neighborFrame(9, address, mac, 64)
	m.data[11] = kind
	return m
}

func neighborSegment() Segment {
	return Segment{ID: "Bridge0", Interface: "Home", IfIndex: 9, Prefixes: []string{"192.0.2.0/24", "2001:db8::/64"}}
}

func TestPhysicalBookkeepingExcludedFromIdentityAndContinuousFence(t *testing.T) {
	for _, m := range []message{
		bookkeepingFrame("224.0.0.1", "01:00:5e:00:00:01", 5),
		bookkeepingFrame("239.255.255.250", "01:00:5e:7f:ff:fa", 5),
		bookkeepingFrame("ff02::1", "33:33:00:00:00:01", 5),
		bookkeepingFrame("ff02::1:ff00:1234", "33:33:ff:00:12:34", 5),
		bookkeepingFrame("255.255.255.255", "ff:ff:ff:ff:ff:ff", 3),
		bookkeepingFrame("192.0.2.0", "ff:ff:ff:ff:ff:ff", 3),
		bookkeepingFrame("192.0.2.255", "ff:ff:ff:ff:ff:ff", 3),
	} {
		segments := []Segment{neighborSegment()}
		_, bookkeeping, err := decodeSegmentNeighbor(m, segments[0])
		if err != nil || !bookkeeping {
			t.Fatal("exact bookkeeping tuple refused", err)
		}
		families := map[byte][]message{2: {}, 10: {}}
		families[m.data[0]] = []message{m}
		devices, err := bindKernelNeighbors(context.Background(), segments, families)
		if err != nil || len(devices) != 0 || len(segments[0].RouterNeighbors) != 0 {
			t.Fatal("bookkeeping became client/router identity", err)
		}
		deleted := m
		deleted.kind = 29
		if err := checkNotifications([]message{m, deleted, m}, segments, nil); err != nil {
			t.Fatal("known multicast/broadcast lifecycle poisoned original scope", err)
		}
	}
}

func TestPhysicalBookkeepingMustMatchEveryRelevantFact(t *testing.T) {
	for _, variant := range []string{"mac-mapping", "mac-unicast", "mac-length", "state", "mixed-state", "flags", "proxy", "unknown-attribute", "cacheinfo-length", "duplicate-attribute", "wrong-type", "wrong-family", "wrong-index", "unicast-address", "off-prefix-broadcast", "broadcast-interior", "broadcast-ipv6", "broadcast-mac", "broadcast-as-client", "point-to-point", "ambiguous-prefix"} {
		t.Run(variant, func(t *testing.T) {
			s := neighborSegment()
			m := bookkeepingFrame("224.0.0.1", "01:00:5e:00:00:01", 5)
			switch variant {
			case "mac-mapping":
				m = bookkeepingFrame("224.0.0.1", "01:00:5e:00:00:02", 5)
			case "mac-unicast":
				m = bookkeepingFrame("224.0.0.1", "02:00:00:00:00:01", 5)
			case "mac-length":
				m = bookkeepingFrame("224.0.0.1", "", 5)
			case "state":
				binary.NativeEndian.PutUint16(m.data[8:10], 2)
			case "mixed-state":
				binary.NativeEndian.PutUint16(m.data[8:10], 64|128)
			case "flags":
				m.data[10] = 16
			case "proxy":
				m.data[10] = 8
			case "unknown-attribute":
				m.data = append(m.data, attr(10, integer(0))...)
			case "cacheinfo-length":
				m.data = append(m.data, attr(3, make([]byte, 15))...)
			case "duplicate-attribute":
				m.data = append(m.data, attr(1, []byte{224, 0, 0, 1})...)
			case "wrong-type":
				m.data[11] = 1
			case "wrong-family":
				m.data[0] = 10
			case "wrong-index":
				binary.NativeEndian.PutUint32(m.data[4:8], 10)
			case "unicast-address":
				m = bookkeepingFrame("192.0.2.20", "01:00:5e:00:00:01", 5)
			case "off-prefix-broadcast":
				m = bookkeepingFrame("192.0.3.255", "ff:ff:ff:ff:ff:ff", 3)
			case "broadcast-interior":
				m = bookkeepingFrame("192.0.2.20", "ff:ff:ff:ff:ff:ff", 3)
			case "broadcast-ipv6":
				m = bookkeepingFrame("ff02::1", "ff:ff:ff:ff:ff:ff", 3)
			case "broadcast-mac":
				m = bookkeepingFrame("192.0.2.255", "01:00:5e:00:00:01", 3)
			case "broadcast-as-client":
				m = neighborFrame(9, "192.0.2.255", "02:00:00:00:00:05", 2)
			case "point-to-point":
				s.Prefixes = []string{"192.0.2.254/31"}
				m = bookkeepingFrame("192.0.2.255", "ff:ff:ff:ff:ff:ff", 3)
			case "ambiguous-prefix":
				s.Prefixes = append(s.Prefixes, "192.0.2.128/25")
				m = bookkeepingFrame("192.0.2.255", "ff:ff:ff:ff:ff:ff", 3)
			}
			if _, _, err := decodeSegmentNeighbor(m, s); err == nil {
				t.Fatal("malformed/unsupported tuple silently ignored")
			}
			// Wrong-index notification is outside selected scope, never a grant;
			// every malformed tuple attached to the selected index still refuses.
			if variant != "wrong-index" && checkNotifications([]message{m}, []Segment{s}, nil) == nil {
				t.Fatal("notification classifier waived rejected dump tuple")
			}
		})
	}
}

func TestPhysicalRouterFlagRetainedAsNegativeRoleForEntireObservedMAC(t *testing.T) {
	segments := []Segment{neighborSegment()}
	routerMAC := "02:00:00:00:00:05"
	router := neighborFrame(9, "2001:db8::5", routerMAC, 2)
	router.data[10] = 128
	other := neighborFrame(9, "192.0.2.5", routerMAC, 4)
	client := neighborFrame(9, "192.0.2.20", "02:00:00:00:00:03", 2)
	devices, err := bindKernelNeighbors(context.Background(), segments, map[byte][]message{2: {other, client}, 10: {router}})
	if err != nil || len(devices) != 1 || devices[0].MAC == routerMAC || len(segments[0].RouterNeighbors) != 2 {
		t.Fatal("router became selected client", err)
	}
	if segments[0].RouterNeighbors[0].Flags != 0 || segments[0].RouterNeighbors[1].Flags != 128 {
		t.Fatal("router bit erased/invented on another actual address")
	}
	// Even the existing textual binder cannot turn the retained router MAC into
	// a client when presented an otherwise ordinary unicast row.
	rows := kernelNeighborRows{"Home": {false: []byte("192.0.2.5 lladdr " + routerMAC + " STALE\n"), true: {}}}
	if devices, err := bindDevices(context.Background(), segments, rows); err != nil || len(devices) != 0 {
		t.Fatal("negative role lost at legacy binding boundary", err)
	}
	for _, state := range []uint16{2, 4, 8, 16, 64, 128} {
		refresh := router
		refresh.data = slices.Clone(router.data)
		binary.NativeEndian.PutUint16(refresh.data[8:10], state)
		if checkNotifications([]message{refresh, other}, segments, devices) != nil {
			t.Fatal("same negative router/client tuple NUD lost original fence")
		}
	}
	for _, variant := range []string{"clear-bit", "set-client-bit", "delete", "mac", "address", "failed"} {
		changed := router
		changed.data = slices.Clone(router.data)
		switch variant {
		case "clear-bit":
			changed.data[10] = 0
		case "set-client-bit":
			changed = neighborFrame(9, "2001:db8::20", devices[0].MAC, 2)
			changed.data[10] = 128
		case "delete":
			changed.kind = 29
		case "mac":
			changed = neighborFrame(9, "2001:db8::5", "02:00:00:00:00:06", 2)
			changed.data[10] = 128
		case "address":
			changed = neighborFrame(9, "2001:db8::6", routerMAC, 2)
			changed.data[10] = 128
		case "failed":
			binary.NativeEndian.PutUint16(changed.data[8:10], 32)
		}
		if checkNotifications([]message{changed}, segments, devices) == nil {
			t.Fatal("changed negative role renewed old review", variant)
		}
	}
}

func TestPhysicalRouterRoleMutationAndRestoreCannotReviveReview(t *testing.T) {
	for _, variant := range []string{"bit", "mac", "address", "prefix"} {
		t.Run(variant, func(t *testing.T) {
			o, model, ctx := newModel(t)
			model.facts.Segments[0].RouterNeighbors = []RouterNeighbor{{Address: "2001:db8::5", MAC: "02:00:00:00:00:05", Flags: 128, Type: 1}}
			r, err := o.Observe(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			detached := r.Snapshot()
			detached.Segments[0].RouterNeighbors[0].Flags = 0
			if o.Verify(ctx, r) != nil {
				t.Fatal("detached negative facts mutated original review")
			}
			original := cloneSnapshot(model.facts)
			switch variant {
			case "bit":
				model.facts.Segments[0].RouterNeighbors[0].Flags = 0
			case "mac":
				model.facts.Segments[0].RouterNeighbors[0].MAC = "02:00:00:00:00:06"
			case "address":
				model.facts.Segments[0].RouterNeighbors[0].Address = "2001:db8::6"
			case "prefix":
				model.facts.Segments[0].Prefixes[0] = "192.0.3.0/24"
			}
			if o.Verify(ctx, r) == nil {
				t.Fatal("negative role/prefix mutation refreshed original review")
			}
			model.facts = original
			if o.Verify(ctx, r) == nil {
				t.Fatal("restored negative role revived invalid review")
			}
		})
	}
}

func TestPhysicalBookkeepingStillConsumesOriginalRowBudget(t *testing.T) {
	m := bookkeepingFrame("224.0.0.1", "01:00:5e:00:00:01", 5)
	frames := make([]message, 4097)
	for i := range frames {
		// Distinct valid IPv4 multicast mappings avoid the duplicate guard.
		address := []byte{239, byte(i >> 16), byte(i >> 8), byte(i)}
		m.data = append(slices.Clone(m.data[:12]), attr(1, address)...)
		m.data = append(m.data, attr(2, []byte{1, 0, 0x5e, address[1] & 0x7f, address[2], address[3]})...)
		frames[i] = m
	}
	if _, err := bindKernelNeighbors(context.Background(), []Segment{neighborSegment()}, map[byte][]message{2: frames, 10: {}}); err == nil {
		t.Fatal("ignored bookkeeping evaded observation budget")
	}
}
