package physicalscope

import (
	"encoding/binary"
	"net/netip"
	"reflect"
	"slices"
	"testing"
)

// Router502 wire lengths/class only; addresses and links are synthetic.
func packetTestForeignMulticast(address string) message {
	m := neighborFrame(12, address, "", 64)
	m.data[11] = 5
	m.data = append(m.data, attr(2, nil)...)
	m.data = append(m.data, attr(3, make([]byte, 16))...)
	m.data = append(m.data, attr(4, make([]byte, 4))...)
	return m
}

func packetTestWithForeignMulticast(m *packetTestModel) {
	link := packetTestNoneLink()
	binary.NativeEndian.PutUint32(link.data[8:12], 69841)
	m.input.links = append(m.input.links, link)
	m.frames[10] = append(m.frames[10], packetTestForeignMulticast("ff02::1234"))
}

func TestIPv4LANPacketScopeForeignMulticastRetainsOpaqueBoundary(t *testing.T) {
	p, m, ctx := packetTestScope(t, packetTestWithForeignMulticast)
	row := m.frames[10][len(m.frames[10])-1]
	n, bookkeeping, err := packetDecodeNeighbor(row, p.topology)
	if err != nil || bookkeeping || n.index != 12 || n.mac != "" || n.kind != 5 || n.address != netip.MustParseAddr("ff02::1234") {
		t.Fatal("foreign multicast became a MAC/client or was discarded")
	}
	_, _, strictErr := decodeSegmentNeighbor(row, Segment{IfIndex: 12})
	assertFenceFailure(t, strictErr, "kernel.bindings.neighbor.bookkeeping-mac")
	_, foreign, err := packetNeighborBoundary(ctx, p.topology, m.frames)
	if err != nil || !slices.Contains(foreign, n) {
		t.Fatal("opaque row missing from complete boundary")
	}
	b, err := p.ObserveMembership(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	if len(b.Facts().Devices) != 3 || slices.ContainsFunc(b.Facts().Devices, func(d Device) bool { return d.IfIndex == 12 || d.MAC == "" }) {
		t.Fatal("opaque row became a client")
	}
	if !reflect.DeepEqual(p.PacketFacts().ExcludedMACs, []string{"02:00:00:00:00:40"}) || !slices.Equal(p.PacketFacts().Intent.ExcludedCIDRs, m.intent.ExcludedCIDRs) {
		t.Fatal("IPv4/IPv6 or offline MAC negatives changed")
	}
	for _, flags := range []uint32{69841, 4241} {
		top := clonePacketTopology(p.topology)
		top.noneLinks[0].Flags = flags
		if _, _, err := packetDecodeNeighbor(row, top); err != nil {
			t.Fatal("captured non-loopback flags refused")
		}
	}
	_, _, err = packetNeighborBoundary(ctx, p.topology, map[byte][]message{2: {}, 10: {row, row}})
	assertFenceFailure(t, err, "kernel.bindings.neighbor.duplicate")
	_, _, err = packetNeighborBoundary(ctx, p.topology, map[byte][]message{2: {}})
	assertFenceFailure(t, err, "kernel.bindings.neighbor.family-missing")
}

func TestIPv4LANPacketScopeForeignMulticastNearMissesRemainRefused(t *testing.T) {
	p, _, _ := packetTestScope(t, packetTestWithForeignMulticast)
	for _, change := range []string{"home", "member", "parent", "known-parent", "missing-link", "ethernet", "loopback", "loopback-flag", "master", "link-parent", "foreign-parent", "ipv4", "unicast-address", "unicast-type", "local-type", "broadcast-type", "state", "flags", "router", "missing-lladdr", "zero-lladdr", "short-lladdr", "missing-cache", "short-cache", "missing-probes", "short-probes", "extra-attribute", "duplicate-attribute", "attribute-flags", "message-type", "owned-address"} {
		t.Run(change, func(t *testing.T) {
			top := clonePacketTopology(p.topology)
			row := packetTestForeignMulticast("ff02::1234")
			switch change {
			case "home":
				binary.NativeEndian.PutUint32(row.data[4:8], uint32(top.home.IfIndex))
			case "member":
				top.home.Members = append(top.home.Members, Link{IfIndex: 12})
			case "parent":
				top.home.Members = append(top.home.Members, Link{IfIndex: 13, ParentIfIndex: 12})
			case "known-parent":
				top.home.Members = append(top.home.Members, Link{IfIndex: 13, Parent: ParentLink{Known: true, IfIndex: 12}})
			case "missing-link":
				top.noneLinks = nil
			case "ethernet":
				top.noneLinks[0].LinkType = 1
			case "loopback":
				top.noneLinks[0].LinkType = 772
			case "loopback-flag":
				top.noneLinks[0].Flags |= 8
			case "master":
				top.noneLinks[0].MasterIfIndex = top.home.IfIndex
			case "link-parent":
				top.noneLinks[0].ParentIfIndex = 13
			case "foreign-parent":
				top.noneLinks[0].ForeignParent = true
			case "ipv4":
				row = packetTestForeignMulticast("224.0.0.1")
			case "unicast-address":
				replaceForeignAttribute(&row, 1, netip.MustParseAddr("2001:db8:2::90").AsSlice(), false)
			case "unicast-type":
				row.data[11] = 1
			case "local-type":
				row.data[11] = 2
			case "broadcast-type":
				row.data[11] = 3
			case "state":
				binary.NativeEndian.PutUint16(row.data[8:10], 4)
			case "flags":
				row.data[10] = 2
			case "router":
				row.data[10] = 128
			case "missing-lladdr":
				replaceForeignAttribute(&row, 2, nil, true)
			case "zero-lladdr":
				replaceForeignAttribute(&row, 2, make([]byte, 6), false)
			case "short-lladdr":
				replaceForeignAttribute(&row, 2, []byte{0}, false)
			case "missing-cache":
				replaceForeignAttribute(&row, 3, nil, true)
			case "short-cache":
				replaceForeignAttribute(&row, 3, make([]byte, 12), false)
			case "missing-probes":
				replaceForeignAttribute(&row, 4, nil, true)
			case "short-probes":
				replaceForeignAttribute(&row, 4, []byte{0}, false)
			case "extra-attribute":
				row.data = append(row.data, attr(8, []byte{0})...)
			case "duplicate-attribute":
				row.data = append(row.data, attr(2, nil)...)
			case "attribute-flags":
				binary.NativeEndian.PutUint16(row.data[14:16], binary.NativeEndian.Uint16(row.data[14:16])|0x8000)
			case "message-type":
				row.kind = 30
			case "owned-address":
				top.addresses = append(top.addresses, packetOwnedAddress{12, "ff02::1234/128"})
			}
			if _, _, err := packetDecodeNeighbor(row, top); err == nil {
				t.Fatal("unknown/owned/near-miss row was accepted")
			}
		})
	}
}

func TestIPv4LANPacketScopeForeignMulticastEventsKeepOriginalFence(t *testing.T) {
	p, m, ctx := packetTestScope(t, packetTestWithForeignMulticast)
	b, err := p.ObserveMembership(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	frozen := p.PacketFacts()
	refresh := packetTestForeignMulticast("ff02::1234")
	m.transport.push(fenceTestDatagram{raw: frame(refresh)})
	waitFenceTestDrained(t, m.transport, 1)
	if err := b.Current(ctx); err != nil {
		t.Fatal("same-class refresh revoked membership", err)
	}
	for index, kind := range []uint16{29, 28} {
		refresh.kind = kind
		m.transport.push(fenceTestDatagram{raw: frame(refresh)})
		waitFenceTestDrained(t, m.transport, index+2)
		if err := p.Current(ctx); err != nil {
			t.Fatal("foreign opaque event discarded A", err)
		}
		if index == 0 {
			assertFenceFailure(t, b.Current(ctx), "packet.membership.changed")
		} else if b.Current(ctx) == nil {
			t.Fatal("restored tuple revived the old membership review")
		}
	}
	if !reflect.DeepEqual(frozen, p.PacketFacts()) || m.opens != 1 {
		t.Fatal("original scope was reissued/mutated")
	}
	// Link changes remain terminal and cannot be repaired by a new dump.
	event := packetTestNoneLink()
	binary.NativeEndian.PutUint16(event.data[2:4], 1)
	m.transport.push(fenceTestDatagram{raw: frame(event)})
	waitFenceTest(t, m.reader.done)
	assertFenceFailure(t, p.Current(ctx), "packet.notifications.owned-link")
	if p.RetainedCurrent(ctx) == nil {
		t.Fatal("link drift lost retained fence")
	}
}

func TestIPv4LANPacketScopeForeignMulticastPreservesOtherFamilyNegatives(t *testing.T) {
	for _, address := range []string{"198.51.100.90", "2001:db8:2::90"} {
		t.Run(address, func(t *testing.T) {
			p, m, ctx := packetTestScope(t, packetTestWithForeignMulticast)
			family := byte(10)
			if netip.MustParseAddr(address).Is4() {
				family = 2
			}
			m.frames[family] = append(m.frames[family], neighborFrame(12, address, projectionClientMAC, 2))
			_, err := p.ObserveMembership(ctx)
			assertFenceFailure(t, err, "packet.membership.foreign")
		})
	}
}

func TestIPv4LANPacketScopeForeignMulticastMalformedEventIsSticky(t *testing.T) {
	p, m, ctx := packetTestScope(t, packetTestWithForeignMulticast)
	row := packetTestForeignMulticast("ff02::1234")
	replaceForeignAttribute(&row, 2, []byte{0}, false)
	m.transport.push(fenceTestDatagram{raw: frame(row)})
	waitFenceTest(t, m.reader.done)
	assertFenceFailure(t, p.Current(ctx), "kernel.bindings.neighbor.bookkeeping-mac")
	// The next complete dump still contains the original good tuple. It cannot
	// resurrect the original fence after a malformed multicast notification.
	if p.Current(ctx) == nil || p.RetainedCurrent(ctx) == nil {
		t.Fatal("fresh dump revived refused original fence")
	}
}
