package physicalscope

import (
	"context"
	"encoding/binary"
	"slices"
	"strings"
	"testing"
)

func vlanFrame(index int, name, mac string, parent, master int, id, protocol uint16, flags uint32, state byte) message {
	m := linkFrame(index, name, "", mac, master)
	binary.NativeEndian.PutUint32(m.data[8:12], 1|0x10000)
	m.data = append(m.data, attr(5, integer(uint32(parent)))...)
	vid, proto := make([]byte, 2), make([]byte, 2)
	binary.NativeEndian.PutUint16(vid, id)
	binary.BigEndian.PutUint16(proto, protocol)
	vflags := append(integer(flags), integer(^uint32(0))...)
	data := append(attr(1, vid), attr(5, proto)...)
	data = append(data, attr(2, vflags)...)
	info := append(attr(1, []byte("vlan\x00")), attr(2, data)...)
	info = append(info, attr(4, []byte("bridge\x00"))...)
	info = append(info, attr(5, attr(1, []byte{state}))...)
	m.data = append(m.data, attr(18, info)...)
	return m
}

func stockVLANParent(index int, name, mac string, master int) message {
	m := linkFrame(index, name, "", mac, master)
	binary.NativeEndian.PutUint32(m.data[8:12], 1|0x10000)
	return m
}

func stockVLANFixture(t *testing.T) ([]message, []message, []message, []nativeSegment) {
	t.Helper()
	native, err := parseNDM([]byte(strings.Replace(ndmFixture(), ndmField("type", "Port"), ndmField("type", "Vlan"), 1)))
	if err != nil {
		t.Fatal(err)
	}
	l, a, r := kernelFixture()
	l[1] = vlanFrame(4, "uplink.17", "02:00:00:00:00:02", 30, 9, 17, 0x8100, 1, 3)
	l = append(l,
		stockVLANParent(30, "uplink", "02:00:00:00:00:02", 0),
		stockVLANParent(20, "radio-a", "02:00:00:00:00:05", 0),
		stockVLANParent(21, "radio-b", "02:00:00:00:00:06", 0),
		vlanFrame(39, "opaque-a", "02:00:00:00:00:05", 20, 9, 17, 0x8100, 5, 3),
		vlanFrame(40, "opaque-b", "02:00:00:00:00:06", 21, 9, 17, 0x8100, 5, 3))
	a = append(a, addressFrame(9, "2001:db8:1::1/64"))
	return l, a, r, native
}

func TestPhysicalStockResidualVLANRetainsActualMembershipAndParents(t *testing.T) {
	l, a, r, native := stockVLANFixture(t)
	segments, err := assembleSegments(Selection{SegmentIDs: []string{"Bridge0"}}, native, true, l, a, r)
	if err != nil || len(segments) != 1 || len(segments[0].Members) != 3 || len(segments[0].Prefixes) != 2 {
		t.Fatal("complete corroborated dual-stack bridge unavailable", err)
	}
	for _, m := range segments[0].Members {
		if !m.Parent.Known || !m.VLAN.Known || m.VLAN.ID != 17 || m.VLAN.Protocol != 0x8100 || m.VLAN.InfoSHA256 == "" {
			t.Fatal("actual parent/VLAN evidence lost")
		}
		if m.IfIndex == 4 {
			if m.Origin != "ndm" || m.NativeID != "GE0/0" {
				t.Fatal("required NDM member lost its unique mapping")
			}
		} else if m.NativeID != "" || m.NativeName != "" || m.Origin != "reviewed-stock-kernel-vlan" || m.Parent.MAC != m.MAC {
			t.Fatal("kernel-only port acquired invented native membership")
		}
	}
}

func TestPhysicalStockResidualVLANRejectsMissingAndConflictingEvidence(t *testing.T) {
	for _, kind := range []string{"missing-required", "wrong-tag", "wrong-protocol", "unknown-flags", "disabled", "parent-kind", "parent-guest-master", "parent-mac", "parent-wan", "child-wan", "foreign-child", "foreign-parent", "dangling-parent", "native-alias", "ordinary-extra", "missing-vlan-data", "no-native-anchor", "conflicting-peer", "guest-selection"} {
		t.Run(kind, func(t *testing.T) {
			l, a, r, n := stockVLANFixture(t)
			selection := Selection{SegmentIDs: []string{"Bridge0"}}
			switch kind {
			case "missing-required":
				l = append(l[:1], l[2:]...)
			case "wrong-tag":
				l[6] = vlanFrame(39, "opaque-a", "02:00:00:00:00:05", 20, 9, 18, 0x8100, 5, 3)
			case "wrong-protocol":
				l[6] = vlanFrame(39, "opaque-a", "02:00:00:00:00:05", 20, 9, 17, 0x88a8, 5, 3)
			case "unknown-flags":
				l[6] = vlanFrame(39, "opaque-a", "02:00:00:00:00:05", 20, 9, 17, 0x8100, 13, 3)
			case "disabled":
				l[6] = vlanFrame(39, "opaque-a", "02:00:00:00:00:05", 20, 9, 17, 0x8100, 5, 0)
			case "parent-kind":
				l[4] = linkFrame(20, "radio-a", "tun", "02:00:00:00:00:05", 0)
			case "parent-guest-master":
				l[4] = stockVLANParent(20, "radio-a", "02:00:00:00:00:05", 10)
			case "parent-mac":
				l[4] = stockVLANParent(20, "radio-a", "02:00:00:00:00:09", 0)
			case "parent-wan":
				r = append(r, routeFrame(20))
			case "child-wan":
				r = append(r, routeFrame(39))
			case "foreign-child":
				l[6].data = append(l[6].data, attr(37, integer(0))...)
			case "foreign-parent":
				l[4].data = append(l[4].data, attr(37, integer(0))...)
			case "dangling-parent":
				l = append(l[:4], l[5:]...)
			case "native-alias":
				n = append(n, nativeSegment{id: "guest-ap", name: "guest-ap", kind: "AccessPoint", mac: "02:00:00:00:00:05", global: "yes", security: "protected"})
			case "ordinary-extra":
				l[6] = stockVLANParent(39, "opaque-a", "02:00:00:00:00:05", 9)
			case "missing-vlan-data":
				l[6] = linkFrame(39, "opaque-a", "vlan", "02:00:00:00:00:05", 9)
			case "no-native-anchor":
				n[1].kind = "Port"
				l[1] = linkFrame(4, "uplink.17", "", "02:00:00:00:00:02", 9)
			case "conflicting-peer":
				l = append(l, vlanFrame(41, "foreign-peer", "02:00:00:00:00:07", 20, 10, 17, 0x8100, 5, 3))
			case "guest-selection":
				selection = Selection{HomeSegmentID: "Home", GuestSegmentIDs: []string{"guest"}}
				n[0].security = "protected"
			}
			if _, err := assembleSegments(selection, n, true, l, a, r); err == nil {
				t.Fatal("residual-member compatibility waived required/negative proof")
			}
		})
	}
}

func TestPhysicalStockResidualVLANMutationAndRestoreCannotReviveReview(t *testing.T) {
	for _, kind := range []string{"parent-index", "parent-mac", "parent-name", "tag", "flags", "bridge", "parent-wan"} {
		t.Run(kind, func(t *testing.T) {
			o, m, ctx := newModel(t)
			m.selection = Selection{Revision: 7, PolicyRevision: 3, SegmentIDs: []string{"Bridge0"}}
			original, a, originalRoutes, n := stockVLANFixture(t)
			current, routes := original, originalRoutes
			o.source.capture = func(context.Context, Selection) ([]Segment, []Device, error) {
				segments, err := assembleSegments(m.selection, n, true, current, a, routes)
				return segments, nil, err
			}
			review, err := o.Observe(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer review.Close()
			copy := review.Snapshot()
			copy.Segments[0].Members[1].Parent.MAC = "changed"
			copy.Segments[0].Members[1].VLAN.ID = 42
			if o.Verify(ctx, review) != nil {
				t.Fatal("detached value metadata mutated the original Review")
			}
			current = slices.Clone(original)
			switch kind {
			case "parent-index":
				current[4] = stockVLANParent(22, "radio-a", "02:00:00:00:00:05", 0)
				current[6] = vlanFrame(39, "opaque-a", "02:00:00:00:00:05", 22, 9, 17, 0x8100, 5, 3)
			case "parent-mac":
				current[4] = stockVLANParent(20, "radio-a", "02:00:00:00:00:09", 0)
			case "parent-name":
				current[4] = stockVLANParent(20, "other-parent", "02:00:00:00:00:05", 0)
			case "tag":
				current[6] = vlanFrame(39, "opaque-a", "02:00:00:00:00:05", 20, 9, 18, 0x8100, 5, 3)
			case "flags":
				current[6] = vlanFrame(39, "opaque-a", "02:00:00:00:00:05", 20, 9, 17, 0x8100, 1, 3)
			case "bridge":
				current[6] = vlanFrame(39, "opaque-a", "02:00:00:00:00:05", 20, 10, 17, 0x8100, 5, 3)
			case "parent-wan":
				routes = append(slices.Clone(originalRoutes), routeFrame(20))
			}
			if o.Verify(ctx, review) == nil {
				t.Fatal("changed VLAN/parent facts refreshed original Review")
			}
			current, routes = original, originalRoutes
			if o.Verify(ctx, review) == nil {
				t.Fatal("restored VLAN tuple revived invalid Review")
			}
		})
	}
}

func TestPhysicalStockVLANParentsParticipateInContinuousFence(t *testing.T) {
	l, a, r, n := stockVLANFixture(t)
	segments, err := assembleSegments(Selection{SegmentIDs: []string{"Bridge0"}}, n, true, l, a, r)
	if err != nil {
		t.Fatal(err)
	}
	parent := l[4]
	deleted := parent
	deleted.kind = 17
	for _, events := range [][]message{{parent}, {deleted, parent}, {addressFrame(20, "fe80::1/64")}, {routeFrame(20)}, {vlanFrame(45, "new-child", "02:00:00:00:00:05", 20, 0, 18, 0x8100, 5, 3)}} {
		if checkNotifications(events, segments, nil) == nil {
			t.Fatal("parent lifecycle/address/WAN/child mutation escaped held fence")
		}
	}
}
