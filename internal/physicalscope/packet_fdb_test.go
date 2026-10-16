package physicalscope

import (
	"context"
	"encoding/binary"
	"net"
	"reflect"
	"slices"
	"testing"
	"time"
)

// Router548's observed shape, with synthetic MAC/indices from the existing
// original-topology fixture. Kernel transport remains modeled in these tests.
func packetFDBFrame(port, master int, mac string) message {
	d := make([]byte, 12)
	d[0] = 7 // AF_BRIDGE: no NDA_DST/IP address exists in this event.
	binary.NativeEndian.PutUint32(d[4:8], uint32(port))
	binary.NativeEndian.PutUint16(d[8:10], 2)
	ll, _ := net.ParseMAC(mac)
	d = append(d, attr(2, ll)...)
	d = append(d, attr(3, make([]byte, 16))...)
	d = append(d, attr(9, integer(uint32(master)))...)
	return message{kind: 28, data: d}
}

func TestPacketFDBOriginalHomeRefreshKeepsMembershipEpoch(t *testing.T) {
	topology := packetCollectorTopology(t)
	s := packetFenceState(topology)
	before := clonePacketTopology(topology)
	for _, mac := range []string{projectionClientMAC, "02:00:00:00:00:40", "02:00:00:00:00:55"} {
		m := packetFDBFrame(topology.home.Members[0].IfIndex, topology.home.IfIndex, mac)
		if err := s.checkPurposeNotifications([]message{m}); err != nil {
			t.Fatal("original Home FDB refresh revoked packet scope", DiagnosticStages(err))
		}
		if _, _, err := packetDecodeNeighbor(m, topology); err == nil {
			t.Fatal("FDB became IP client/neighbor evidence")
		}
	}
	if s.membershipEpoch != 0 || len(s.membershipClasses) != 0 || !reflect.DeepEqual(s.packet.original, before) {
		t.Fatal("FDB changed membership or original topology")
	}
}

func TestPacketFDBUnsupportedShapesAndTopologyRefuse(t *testing.T) {
	base := packetCollectorTopology(t)
	for _, change := range []string{"delete", "flags", "sequence", "sender", "family", "pad", "short", "trailing", "state-stale", "state-mixed", "ndm-flags", "type", "missing-master", "wrong-master", "signed-master", "root-index", "unknown-port", "guest-port", "duplicate-attribute", "nested-attribute", "network-attribute", "padding", "extra-attribute", "missing-cache", "short-cache", "short-mac", "zero-mac", "multicast-mac", "not-home", "guest-home", "raw-port-master", "member-master", "member-name", "member-mac", "member-flags", "unbound-member", "missing-native-id", "down-port", "foreign-parent", "parent", "vlan", "bridge-kind", "raw-port-missing", "duplicate-port"} {
		t.Run(change, func(t *testing.T) {
			top := clonePacketTopology(base)
			port := top.home.Members[0].IfIndex
			m := packetFDBFrame(port, top.home.IfIndex, projectionClientMAC)
			modifyRaw := func(f func(*Link)) {
				for i := range top.links {
					if top.links[i].IfIndex == port {
						f(&top.links[i])
					}
				}
			}
			switch change {
			case "delete":
				m.kind = 29
			case "flags":
				m.flags = 2
			case "sequence":
				m.seq = 1
			case "sender":
				m.pid = 1
			case "family":
				m.data[0] = 17
			case "pad":
				m.data[1] = 1
			case "short":
				m.data = m.data[:11]
			case "trailing":
				m.data = append(m.data, 0)
			case "state-stale":
				binary.NativeEndian.PutUint16(m.data[8:10], 4)
			case "state-mixed":
				binary.NativeEndian.PutUint16(m.data[8:10], 6)
			case "ndm-flags":
				m.data[10] = 2
			case "type":
				m.data[11] = 1
			case "missing-master":
				m.data = m.data[:len(m.data)-8]
			case "wrong-master":
				m = packetFDBFrame(port, top.home.IfIndex+1, projectionClientMAC)
			case "signed-master":
				m = packetFDBFrame(port, -1, projectionClientMAC)
			case "root-index":
				m = packetFDBFrame(top.home.IfIndex, top.home.IfIndex, projectionClientMAC)
			case "unknown-port":
				m = packetFDBFrame(77, top.home.IfIndex, projectionClientMAC)
			case "guest-port":
				m = packetFDBFrame(5, top.home.IfIndex, projectionClientMAC)
			case "duplicate-attribute":
				m.data = append(m.data, attr(9, integer(uint32(top.home.IfIndex)))...)
			case "nested-attribute":
				binary.NativeEndian.PutUint16(m.data[14:16], 0x8002)
			case "network-attribute":
				binary.NativeEndian.PutUint16(m.data[14:16], 0x4002)
			case "padding":
				m.data[22] = 1
			case "extra-attribute":
				m.data = append(m.data, attr(1, []byte{192, 0, 2, 20})...)
			case "missing-cache":
				m.data = append(m.data[:24], m.data[44:]...)
			case "short-cache":
				binary.NativeEndian.PutUint16(m.data[24:26], 16)
			case "short-mac":
				binary.NativeEndian.PutUint16(m.data[12:14], 9)
			case "zero-mac":
				clear(m.data[16:22])
			case "multicast-mac":
				m.data[16] |= 1
			case "not-home":
				top.home.Home = false
			case "guest-home":
				top.home.Guest = true
			case "raw-port-master":
				modifyRaw(func(l *Link) { l.MasterIfIndex++ })
			case "member-master":
				top.home.Members[0].MasterIfIndex++
			case "member-name":
				top.home.Members[0].Interface = "other"
			case "member-mac":
				top.home.Members[0].MAC = "02:00:00:00:00:99"
			case "member-flags":
				top.home.Members[0].Flags ^= 0x10000
			case "unbound-member":
				top.home.Members[0].Origin = "kernel"
			case "missing-native-id":
				top.home.Members[0].NativeID = ""
			case "down-port":
				top.home.Members[0].Flags &^= 1
				modifyRaw(func(l *Link) { l.Flags &^= 1 })
			case "foreign-parent":
				top.home.Members[0].ForeignParent = true
				modifyRaw(func(l *Link) { l.ForeignParent = true })
			case "parent":
				top.home.Members[0].ParentIfIndex = 77
				modifyRaw(func(l *Link) { l.ParentIfIndex = 77 })
			case "vlan":
				top.home.Members[0].VLAN = VLANFacts{Known: true, ID: 2}
				modifyRaw(func(l *Link) { l.VLAN = top.home.Members[0].VLAN })
			case "bridge-kind":
				for i := range top.links {
					if top.links[i].IfIndex == top.home.IfIndex {
						top.links[i].Kind = "bond"
					}
				}
			case "raw-port-missing":
				top.links = slices.DeleteFunc(top.links, func(l Link) bool { return l.IfIndex == port })
			case "duplicate-port":
				top.home.Members = append(top.home.Members, top.home.Members[0])
			}
			s := packetFenceState(top)
			if err := s.checkPurposeNotifications([]message{m}); err == nil {
				t.Fatal("unsupported FDB shape/topology admitted")
			}
			if s.membershipEpoch != 0 || len(s.membershipClasses) != 0 {
				t.Fatal("invalid FDB became membership evidence")
			}
		})
	}
}

func TestPacketFDBOriginalCollectorPendingAndScopeNegatives(t *testing.T) {
	p, m, ctx := packetTestScope(t)
	initial := p.PacketFacts()
	b, err := p.ObserveMembership(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	before := b.Facts()
	for i := 0; i < 8; i++ {
		event := packetFDBFrame(p.topology.home.Members[0].IfIndex, p.topology.home.IfIndex, "02:00:00:00:00:40")
		m.transport.push(fenceTestDatagram{raw: frame(event)})
	}
	if err := p.Current(ctx); err != nil {
		t.Fatal("FDB refresh revoked original scope", DiagnosticStages(err))
	}
	if err := p.RetainedCurrent(ctx); err != nil {
		t.Fatal(err)
	}
	if err := b.Current(ctx); err != nil {
		t.Fatal("FDB changed IP membership epoch", DiagnosticStages(err))
	}
	if !reflect.DeepEqual(initial, p.PacketFacts()) || !reflect.DeepEqual(before, b.Facts()) || !slices.Equal(initial.ExcludedMACs, []string{"02:00:00:00:00:40"}) || m.opens != 1 {
		t.Fatal("FDB changed original facts, negatives, or fence")
	}
	// A subsequent ordinary IP binding still moves B, never structural A.
	m.transport.push(fenceTestDatagram{raw: frame(neighborFrame(9, "192.0.2.88", "02:00:00:00:00:88", 2))})
	if b.Current(ctx) == nil {
		t.Fatal("IP membership changes hidden by FDB classifier")
	}
	if err := p.Current(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestPacketFDBPendingBeforeFirstCheckpoint(t *testing.T) {
	f := newFenceTestTransport()
	r := newOriginalFenceCollector(f.source())
	t.Cleanup(r.close)
	top := packetCollectorTopology(t)
	f.push(fenceTestDatagram{raw: frame(packetFDBFrame(top.home.Members[0].IfIndex, top.home.IfIndex, projectionClientMAC))})
	waitFenceTestDrained(t, f, 1)
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	if epoch, err := r.checkPacket(ctx, top); err != nil || epoch != 0 {
		t.Fatal("pending original FDB revoked scope or moved epoch", epoch, DiagnosticStages(err))
	}
}

func TestPacketFDBMalformedOrStructuralEventPermanentlyRevokes(t *testing.T) {
	for _, change := range []string{"malformed", "newlink", "delete-newlink"} {
		t.Run(change, func(t *testing.T) {
			p, m, ctx := packetTestScope(t)
			port := p.topology.home.Members[0]
			good := packetFDBFrame(port.IfIndex, p.topology.home.IfIndex, projectionClientMAC)
			m.transport.push(fenceTestDatagram{raw: frame(good)})
			bad := good
			bad.data = slices.Clone(good.data)
			switch change {
			case "malformed":
				bad.data[10] = 2
			default:
				bad = linkFrame(port.IfIndex, port.Interface, port.Kind, port.MAC, port.MasterIfIndex)
				if change == "delete-newlink" {
					bad.kind = 17
				}
			}
			m.transport.push(fenceTestDatagram{raw: frame(bad)})
			if change == "delete-newlink" {
				restored := bad
				restored.kind = 16
				m.transport.push(fenceTestDatagram{raw: frame(restored)})
			}
			m.transport.push(fenceTestDatagram{raw: frame(good)})
			if p.Current(ctx) == nil || p.RetainedCurrent(ctx) == nil {
				t.Fatal("changed topology/malformed stream allowed scope forward or retained use")
			}
			if p.Current(ctx) == nil || m.opens != 1 {
				t.Fatal("original fence revived after refusal")
			}
		})
	}
}

func TestPacketFDBIsNotSharedNeighborOrFiniteIdentityProof(t *testing.T) {
	top := packetCollectorTopology(t)
	event := packetFDBFrame(top.home.IfIndex, top.home.IfIndex, projectionClientMAC)
	for _, check := range []func([]message, Snapshot) error{checkSnapshotNotifications, checkFiniteIPv4Notifications} {
		if err := check([]message{event}, Snapshot{Segments: []Segment{top.home}}); err == nil {
			t.Fatal("shared/finite classifier accepted unsupported FDB on selected root")
		}
	}
	for _, intent := range []IPv4LANPacketIntent{{Revision: 1, PolicyRevision: 1, Mode: "selected", NewDevices: "inherit", SegmentIDs: []string{"Bridge0"}}, {Revision: 1, PolicyRevision: 1, Mode: "lan_except", NewDevices: "exclude", SegmentIDs: []string{"Bridge0"}}} {
		if _, err := validateIPv4LANPacketIntent(intent); err == nil {
			t.Fatal("finite membership granted whole-Home packet purpose")
		}
	}
}
