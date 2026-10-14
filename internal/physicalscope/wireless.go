package physicalscope

import (
	"encoding/binary"
	"slices"
	"strconv"
)

// Linux v4.9 wireless_send_event/rtnetlink_ifinfo_prep emits a partial
// RTM_NEWLINK: IFNAME + WIRELESS, AF_UNSPEC, dev type/index/flags, change=0.
// Missing MAC/master/LINKINFO is no topology assertion. Only the original
// actual NDM AccessPoint member can match this narrow notification shape.
// https://raw.githubusercontent.com/torvalds/linux/v4.9/net/wireless/wext-core.c
func originalWirelessNotification(m message, segments []Segment) (bool, error) {
	if len(m.data) < 16 {
		return false, nil // Preserve the ordinary link decoder's refusal.
	}
	a, err := attrs(m.data[16:])
	if err != nil || a[11] == nil {
		return false, nil
	}
	name, err := wireString(a[3], 15)
	if err != nil {
		return false, at("notifications.wireless.name", err)
	}
	index := int(int32(binary.NativeEndian.Uint32(m.data[4:8])))
	var original Link
	matches, master := 0, 0
	for _, s := range segments {
		for _, member := range s.Members {
			if member.IfIndex == index || member.Interface == name {
				original = member
				master = s.IfIndex
				matches++
			}
		}
	}
	if matches == 0 {
		return false, nil // Unrelated/root/parent LINK still uses every old guard.
	}
	if matches != 1 || index <= 0 || index != original.IfIndex || name != original.Interface {
		return false, at("notifications.wireless.binding", nil)
	}
	if original.Origin != "ndm" || original.NativeType != "AccessPoint" || original.NativeID == "" || original.Kind != "" || original.LinkType != 1 || original.MasterIfIndex != master || original.VLAN.Known || original.ForeignParent || original.Flags&(1|0x10000) != 1|0x10000 {
		reason := "flags"
		switch {
		case original.Origin != "ndm":
			reason = "origin"
		case original.NativeType != "AccessPoint":
			reason = "native-type"
		case original.NativeID == "":
			reason = "native-id"
		case original.Kind != "":
			reason = "kind"
		case original.LinkType != 1:
			reason = "link-type"
		case original.MasterIfIndex != master:
			reason = "master"
		case original.VLAN.Known:
			reason = "vlan"
		case original.ForeignParent:
			reason = "foreign-parent"
		}
		return false, at("notifications.wireless.role", at("notifications.wireless.role."+reason, nil))
	}
	if err := wirelessNotificationShape(m, a, original); err != nil {
		return false, err
	}
	return true, nil
}

// packetForeignWirelessNotification accepts the same narrow WEXT shape from an
// ORIGINAL link of the IPv4 LAN packet topology outside Home (for example a
// guest access point). boundarySegments() turns every such link into its own
// synthetic segment without NDM facts, so the Home classifier above refused
// any station event on it with notifications.wireless.role.origin (router
// probe 491). The shape carries no MAC, master or LINKINFO, so it cannot
// assert a topology change; an actual change still arrives as an ordinary
// RTM_NEWLINK and keeps every old guard. Home links stay with the original
// NDM classifier. Index and name must BOTH match one original link: a reused
// index or a renamed interface is refused, never matched by either key.
func packetForeignWirelessNotification(m message, t ipv4LANPacketTopology) (bool, error) {
	if len(m.data) < 16 {
		return false, nil
	}
	a, err := attrs(m.data[16:])
	if err != nil || a[11] == nil {
		return false, nil
	}
	name, err := wireString(a[3], 15)
	if err != nil {
		return false, at("notifications.wireless.name", err)
	}
	index := int(int32(binary.NativeEndian.Uint32(m.data[4:8])))
	if index == t.home.IfIndex || name == t.home.Interface {
		return false, nil
	}
	for _, member := range t.home.Members {
		if member.IfIndex == index || member.Interface == name || member.Parent.Known && (member.Parent.IfIndex == index || member.Parent.Interface == name) {
			return false, nil
		}
	}
	var original Link
	matches := 0
	for _, l := range t.links {
		if l.IfIndex == index || l.Interface == name {
			original = l
			matches++
		}
	}
	if matches == 0 {
		return false, nil // Unknown links keep the ordinary decoder's guards.
	}
	if matches != 1 || index <= 0 || index != original.IfIndex || name != original.Interface {
		return false, at("notifications.wireless.foreign.binding", nil)
	}
	same := func(l Link) bool { return l.IfIndex == original.IfIndex }
	if original.Kind != "" || original.LinkType != 1 || slices.ContainsFunc(t.noneLinks, same) || slices.ContainsFunc(t.loopbackLinks, same) {
		return false, at("notifications.wireless.foreign.link", nil)
	}
	if err := wirelessNotificationShape(m, a, original); err != nil {
		return false, err
	}
	return true, nil
}

// wirelessNotificationShape checks the exact partial WEXT RTM_NEWLINK shape
// against the original link facts: header, plain IFNAME/WIRELESS attributes
// and one bounded IWEVCUSTOM payload.
func wirelessNotificationShape(m message, a map[uint16][]byte, original Link) error {
	if m.kind != 16 || m.flags != 0 || m.seq != 0 || m.pid != 0 || m.data[0] != 0 || m.data[1] != 0 || binary.NativeEndian.Uint16(m.data[2:4]) != original.LinkType || binary.NativeEndian.Uint32(m.data[8:12]) != original.Flags || binary.NativeEndian.Uint32(m.data[12:16]) != 0 {
		return at("notifications.wireless.header", nil)
	}
	if len(a) != 2 {
		return at("notifications.wireless.attributes", nil)
	}
	// The emitter uses plain, non-nested IFNAME/WIRELESS attrs. attrs above
	// already checked every length/alignment/duplicate; retain exact type bits.
	for raw := m.data[16:]; len(raw) > 0; {
		typeBits := binary.NativeEndian.Uint16(raw[2:4])
		if typeBits != 3 && typeBits != 11 {
			return at("notifications.wireless.attributes", nil)
		}
		n := int(binary.NativeEndian.Uint16(raw[:2]))
		raw = raw[(n+3)&^3:]
	}
	return validateWirelessCustom(a[11])
}

// A single native-ABI IWEVCUSTOM iw_point event, at most IW_CUSTOM_MAX=256
// bytes. The driver-specific bytes/flags are opaque advisory data; they never
// become a binding, a selected source, or a substitute for the full captures.
// Association/expiry/setter/unknown commands and packed/concatenated streams
// remain unsupported. The native rtmsg and WEXT emitter have distinct shapes.
func validateWirelessCustom(raw []byte) error {
	const custom = 0x8c02
	const maxCustom = 256
	const lcp = strconv.IntSize / 8
	const point = 2 * lcp
	if len(raw) < point || len(raw) > point+maxCustom || int(binary.NativeEndian.Uint16(raw[:2])) != len(raw) {
		return at("notifications.wireless.payload.length", nil)
	}
	if binary.NativeEndian.Uint16(raw[2:4]) != custom {
		return at("notifications.wireless.payload.command", nil)
	}
	for _, padding := range raw[4:lcp] {
		if padding != 0 {
			return at("notifications.wireless.payload.padding", nil)
		}
	}
	if int(binary.NativeEndian.Uint16(raw[lcp:lcp+2])) != len(raw)-point {
		return at("notifications.wireless.payload.tokens", nil)
	}
	// iw_point.flags and its trailing ABI padding are copied from iwreq_data
	// by the kernel. They carry no link topology and need not be zero.
	return nil
}
