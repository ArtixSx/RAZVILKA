package physicalscope

import (
	"encoding/binary"
	"net"
)

// Router548 observed this unsolicited AF_BRIDGE learning refresh on an
// original Home port. Only the whole-Home/lan_except+inherit packet purpose
// calls this classifier. FDB carries no IP association: it cannot create a
// device, change membership B, remove literal MAC exclusions or issue authority.
// Full/finite neighbor grammar and the structural fence remain unchanged.
// DEL, other states and extended FDB shapes are deliberately unsupported.
func packetHomeFDBRefresh(m message, t ipv4LANPacketTopology) bool {
	// Exact ndmsg + LLADDR6/CACHEINFO16/MASTER4, including aligned padding.
	if m.kind != 28 || m.flags != 0 || m.seq != 0 || m.pid != 0 || len(m.data) != 52 || m.data[0] != 7 || m.data[1] != 0 || m.data[2] != 0 || m.data[3] != 0 || binary.NativeEndian.Uint16(m.data[8:10]) != 2 || m.data[10] != 0 || m.data[11] != 0 {
		return false
	}
	a, err := attrs(m.data[12:])
	if err != nil || len(a) != 3 || len(a[2]) != 6 || len(a[3]) != 16 || len(a[9]) != 4 || !validMAC(net.HardwareAddr(a[2]).String()) {
		return false
	}
	// attrs checked lengths/duplicates. Retain exact non-nested type bits and
	// zero padding too; cache timestamps are opaque advisory counters only.
	for raw := m.data[12:]; len(raw) > 0; {
		kind := binary.NativeEndian.Uint16(raw[2:4])
		if kind != 2 && kind != 3 && kind != 9 {
			return false
		}
		n := int(binary.NativeEndian.Uint16(raw[:2]))
		aligned := (n + 3) &^ 3
		for _, b := range raw[n:aligned] {
			if b != 0 {
				return false
			}
		}
		raw = raw[aligned:]
	}
	port := int(int32(binary.NativeEndian.Uint32(m.data[4:8])))
	master := int(int32(binary.NativeEndian.Uint32(a[9])))
	if port <= 0 || master <= 0 || port == master || master != t.home.IfIndex || !t.home.Home || t.home.Guest || len(t.home.Members) == 0 || len(t.home.Members) > 64 || len(t.links) > 4096 {
		return false
	}
	bridges, members, rawPorts := 0, 0, 0
	var member Link
	for _, l := range t.home.Members {
		if l.IfIndex == port {
			member = l
			members++
		}
	}
	// Bind to an originally corroborated direct NDM member. VLAN/indirect,
	// foreign-parent and opaque attachments need their own observed contract.
	if members != 1 || member.Origin != "ndm" || member.NativeID == "" || member.NativeType == "" || member.Kind != "" || member.LinkType != 1 || member.Flags&(1|8) != 1 || member.MasterIfIndex != master || member.ParentIfIndex != 0 || member.ForeignParent || member.Parent != (ParentLink{}) || member.VLAN != (VLANFacts{}) || member.SlaveKind != "" && member.SlaveKind != "bridge" || member.BridgeStateKnown && member.BridgePortState != 3 {
		return false
	}
	member.NativeID, member.NativeName, member.NativeInterfaceName, member.NativeType, member.Origin = "", "", "", "", ""
	for _, l := range t.links {
		if l.IfIndex == master {
			if l.Interface != t.home.Interface || l.MAC != t.home.MAC || !validMAC(l.MAC) || l.Kind != "bridge" || l.LinkType != 1 || l.Flags&(1|8) != 1 || l.MasterIfIndex != 0 || l.ParentIfIndex != 0 || l.ForeignParent {
				return false
			}
			bridges++
		}
		if l.IfIndex == port {
			if l != member {
				return false
			}
			rawPorts++
		}
	}
	return bridges == 1 && rawPorts == 1
}
