package physicalscope

import "strings"

// This private stock-only residual-member check runs AFTER every required NDM
// member matched exactly once. The bridge's complete actual kernel membership
// remains the physical fact; an unlisted port never acquires a native identity.
func reviewedStockKernelVLAN(s Segment, member Link, links map[int]kernelLink, wan map[int]bool, native []nativeSegment) error {
	const upAndLowerUp = uint32(1 | 0x10000)
	const reviewedFlags = uint32(1 | 4) // REORDER_HDR | LOOSE_BINDING
	if member.Kind != "vlan" {
		return at("kernel.corroboration.member.kernel-unmatched", nil)
	}
	if !s.Home || s.Guest || member.NativeID != "" {
		return at("kernel.corroboration.member.kernel-vlan.scope", nil)
	}
	if !member.VLAN.Known || member.VLAN.Unsupported || member.VLAN.ID == 0 || member.VLAN.Protocol != 0x8100 {
		return at("kernel.corroboration.member.kernel-vlan.metadata", nil)
	}
	if !member.VLAN.FlagsKnown || member.VLAN.Flags != reviewedFlags || member.VLAN.FlagsMask != ^uint32(0) {
		return at("kernel.corroboration.member.kernel-vlan.flags", nil)
	}
	if member.MasterIfIndex != s.IfIndex || member.LinkType != 1 || member.Flags&upAndLowerUp != upAndLowerUp || member.ForeignParent {
		return at("kernel.corroboration.member.kernel-vlan.attachment", nil)
	}
	if member.SlaveKind != "bridge" || !member.BridgeStateKnown || member.BridgePortState != 3 {
		return at("kernel.corroboration.member.kernel-vlan.bridge-state", nil)
	}
	if wan[member.IfIndex] {
		return at("kernel.corroboration.member.kernel-vlan.wan", nil)
	}
	p := member.Parent
	if !p.Known || p.IfIndex != member.ParentIfIndex || p.IfIndex == member.IfIndex || p.Kind != "" || p.LinkType != 1 || p.MasterIfIndex != 0 || p.ForeignParent || p.ParentIfIndex != 0 && p.ParentIfIndex != p.IfIndex {
		return at("kernel.corroboration.member.kernel-vlan.parent", nil)
	}
	if p.Flags&upAndLowerUp != upAndLowerUp {
		return at("kernel.corroboration.member.kernel-vlan.parent-state", nil)
	}
	if !validMAC(p.MAC) || p.MAC != member.MAC {
		return at("kernel.corroboration.member.kernel-vlan.parent-mac", nil)
	}
	if wan[p.IfIndex] {
		return at("kernel.corroboration.member.kernel-vlan.parent-wan", nil)
	}
	// A known native identity cannot be silently reclassified as an unlisted
	// port/parent, including any guest/public/WAN alias sharing its MAC.
	for _, v := range native {
		if v.mac != "" && (strings.EqualFold(v.mac, member.MAC) || strings.EqualFold(v.mac, p.MAC)) {
			return at("kernel.corroboration.member.kernel-vlan.native-alias", nil)
		}
	}
	anchors := 0
	for _, a := range s.Members {
		if a.NativeID == "" || a.NativeType != "Vlan" {
			continue
		}
		if !a.VLAN.Known || a.VLAN.Unsupported || !a.Parent.Known || a.ForeignParent || a.VLAN.ID == 0 || a.VLAN.Protocol != 0x8100 {
			return at("kernel.corroboration.member.kernel-vlan.anchor-metadata", nil)
		}
		anchors++
		if a.VLAN.ID != member.VLAN.ID || a.VLAN.Protocol != member.VLAN.Protocol {
			return at("kernel.corroboration.member.kernel-vlan.anchor-tuple", nil)
		}
	}
	if anchors != 1 {
		return at("kernel.corroboration.member.kernel-vlan.anchor-count", nil)
	}
	for _, other := range links {
		if other.IfIndex == member.IfIndex || other.ParentIfIndex != p.IfIndex {
			continue
		}
		if other.VLAN.Known && other.VLAN.ID == member.VLAN.ID && other.VLAN.Protocol == member.VLAN.Protocol && other.master != s.IfIndex {
			return at("kernel.corroboration.member.kernel-vlan.peer-conflict", nil)
		}
	}
	return nil
}
