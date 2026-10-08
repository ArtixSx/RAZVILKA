package physicalscope

import (
	"context"
	"encoding/binary"
	"net/netip"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/ArtixSx/razvilka/internal/devices"
)

func assembleSegments(selection Selection, native []nativeSegment, stock bool, linkFrames, addressFrames, routeFrames []message) ([]Segment, error) {
	var err error
	links := map[int]kernelLink{}
	names := map[string]kernelLink{}
	for _, m := range linkFrames {
		link, err := decodeLink(m)
		if err != nil {
			return nil, at("kernel.corroboration.link.decode", err)
		}
		if _, ok := links[link.IfIndex]; ok {
			return nil, at("kernel.corroboration.link.duplicate-index", nil)
		}
		if _, ok := names[link.Interface]; ok {
			return nil, at("kernel.corroboration.link.duplicate-name", nil)
		}
		links[link.IfIndex], names[link.Interface] = link, link
	}
	wan := map[int]bool{}
	for _, m := range routeFrames {
		indices, err := decodeWAN(m)
		if err != nil {
			return nil, at("kernel.corroboration.route.decode", err)
		}
		for _, index := range indices {
			wan[index] = true
		}
	}
	selected := append([]string{selection.HomeSegmentID}, selection.GuestSegmentIDs...)
	if len(selection.SegmentIDs) > 0 {
		if !stock {
			return nil, at("kernel.corroboration.selection.linux-home-required", nil)
		} // Linux must explicitly identify Home.
		home := ""
		guests := []string{}
		for _, id := range selection.SegmentIDs {
			v, err := resolveNative(native, id)
			if err != nil {
				return nil, at("kernel.corroboration.selection.native-resolve", err)
			}
			if v.kind != "Bridge" {
				return nil, at("kernel.corroboration.selection.native-kind", nil)
			}
			if v.global != "no" {
				return nil, at("kernel.corroboration.selection.native-global", nil)
			}
			switch v.security {
			case "private":
				if home != "" {
					return nil, at("kernel.corroboration.selection.multiple-home", nil)
				}
				home = id
			case "protected":
				guests = append(guests, id)
			default:
				return nil, at("kernel.corroboration.selection.native-security", nil)
			}
		}
		if home == "" {
			return nil, at("kernel.corroboration.selection.home-missing", nil)
		}
		selected = append([]string{home}, guests...)
	}
	segments := make([]Segment, 0, len(selected))
	nativeByInterface := map[string]nativeSegment{}
	for i, id := range selected {
		resolved := nativeSegment{id: id, name: id, osName: id}
		if stock {
			resolved, err = resolveNative(native, id)
			if err != nil {
				return nil, at("kernel.corroboration.native.resolve", err)
			}
			resolved, err = validateNativeBridge(resolved)
			if err != nil {
				return nil, err
			}
			role := "private"
			if i > 0 {
				role = "protected"
			}
			if resolved.kind != "Bridge" {
				return nil, at("kernel.corroboration.native.kind", nil)
			}
			if resolved.global != "no" {
				return nil, at("kernel.corroboration.native.global", nil)
			}
			if resolved.security != role {
				return nil, at("kernel.corroboration.native.security", nil)
			}
			if resolved.link != "up" {
				return nil, at("kernel.corroboration.native.link", nil)
			}
			if resolved.state != "up" {
				return nil, at("kernel.corroboration.native.state", nil)
			}
			if resolved.connected != "yes" {
				return nil, at("kernel.corroboration.native.connected", nil)
			}
		}
		link, ok := names[resolved.osName]
		if stock {
			count := 0
			closest := bridgeMatchNoMAC
			for _, candidate := range links {
				match, err := matchNativeBridge(resolved, candidate, addressFrames)
				if err != nil {
					return nil, err
				}
				if match > closest {
					closest = match
				}
				if match == bridgeMatchComplete {
					link = candidate
					count++
				}
			}
			if count == 0 {
				// This closed result reports only the furthest comparison. No
				// candidate becomes selected evidence until every check passes.
				switch closest {
				case bridgeMatchNoMAC:
					return nil, at("kernel.corroboration.bridge.match.mac", nil)
				case bridgeMatchWrongKind:
					return nil, at("kernel.corroboration.bridge.match.kind", nil)
				case bridgeMatchWrongLinkType:
					return nil, at("kernel.corroboration.bridge.match.link-type", nil)
				case bridgeMatchWrongPrefixes:
					return nil, at("kernel.corroboration.bridge.match.prefixes", nil)
				case bridgeMatchWrongAddress:
					return nil, at("kernel.corroboration.bridge.match.host-address", nil)
				default:
					return nil, at("kernel.corroboration.bridge.match.unknown", nil)
				}
			}
			if count != 1 {
				return nil, at("kernel.corroboration.bridge.match.ambiguous", nil)
			}
			ok = count == 1
		}
		if !ok {
			return nil, at("kernel.corroboration.bridge.missing", nil)
		}
		if !link.up {
			return nil, at("kernel.corroboration.bridge.down", nil)
		}
		if link.kind != "bridge" {
			return nil, at("kernel.corroboration.bridge.kind", nil)
		}
		if link.linkType != 1 {
			return nil, at("kernel.corroboration.bridge.link-type", nil)
		}
		if !validMAC(link.MAC) {
			return nil, at("kernel.corroboration.bridge.mac", nil)
		}
		if wan[link.IfIndex] {
			return nil, at("kernel.corroboration.bridge.wan", nil)
		}
		if link.master != 0 {
			return nil, at("kernel.corroboration.bridge.master", nil)
		}
		if stock && resolved.mac != link.MAC {
			return nil, at("kernel.corroboration.bridge.native-mac", nil)
		}
		if _, ok := nativeByInterface[link.Interface]; ok {
			return nil, at("kernel.corroboration.bridge.duplicate-selection", nil)
		}
		nativeByInterface[link.Interface] = resolved
		s := Segment{ID: resolved.id, NativeName: resolved.name, NativeInterfaceName: resolved.osName, NativeIndex: resolved.index, Interface: link.Interface, IfIndex: link.IfIndex, MAC: link.MAC, Home: i == 0, Guest: i > 0, Prefixes: []string{}, LinkAddresses: []string{}, Members: []Link{}}
		for _, member := range links {
			if member.master != link.IfIndex {
				continue
			}
			if wan[member.IfIndex] {
				return nil, at("kernel.corroboration.member.wan", nil)
			}
			if member.linkType != 1 {
				return nil, at("kernel.corroboration.member.link-type", nil)
			}
			if !validMAC(member.MAC) {
				return nil, at("kernel.corroboration.member.mac", nil)
			}
			if member.kind == "bridge" {
				return nil, at("kernel.corroboration.member.nested-bridge", nil)
			}
			facts := member.Link
			facts.Origin = "kernel"
			if facts.VLAN.Known {
				parent, ok := links[facts.ParentIfIndex]
				if !ok || facts.ForeignParent || parent.ForeignParent || parent.IfIndex == facts.IfIndex {
					return nil, at("kernel.corroboration.member.vlan-parent", nil)
				}
				facts.Parent = ParentLink{Known: true, Interface: parent.Interface, IfIndex: parent.IfIndex, MAC: parent.MAC, Kind: parent.kind, LinkType: parent.linkType, Flags: parent.Flags, MasterIfIndex: parent.master, ParentIfIndex: parent.ParentIfIndex, ForeignParent: parent.ForeignParent}
			}
			s.Members = append(s.Members, facts)
		}
		if len(s.Members) == 0 || len(s.Members) > 64 {
			return nil, at("kernel.corroboration.member.count", nil)
		}
		sort.Slice(s.Members, func(i, j int) bool { return s.Members[i].IfIndex < s.Members[j].IfIndex })
		if stock {
			matched := map[int]bool{}
			for _, member := range resolved.members {
				v, err := resolveNative(native, member)
				if err != nil {
					return nil, at("kernel.corroboration.member.native-resolve", err)
				}
				count := 0
				position := -1
				for j, m := range s.Members {
					if nativeMemberMatches(v, links[m.IfIndex]) {
						count++
						position = j
					}
				}
				if count == 0 {
					return nil, at("kernel.corroboration.member.native-match.missing", nil)
				}
				if count != 1 {
					return nil, at("kernel.corroboration.member.native-match.ambiguous", nil)
				}
				if matched[s.Members[position].IfIndex] {
					return nil, at("kernel.corroboration.member.native-match.reused", nil)
				}
				m := &s.Members[position]
				matched[m.IfIndex] = true
				m.NativeID, m.NativeName, m.NativeInterfaceName, m.NativeType = v.id, v.name, v.osName, v.kind
				m.Origin = "ndm"
			}
			for j := range s.Members {
				m := &s.Members[j]
				if matched[m.IfIndex] {
					continue
				}
				if err := reviewedStockKernelVLAN(s, *m, links, wan, native); err != nil {
					return nil, err
				}
				m.Origin = "reviewed-stock-kernel-vlan"
			}
		}
		segments = append(segments, s)
	}
	for _, m := range addressFrames {
		if len(m.data) < 8 {
			return nil, at("kernel.corroboration.address.frame-shape", nil)
		}
		index := int(binary.NativeEndian.Uint32(m.data[4:8]))
		position := -1
		for i, s := range segments {
			if s.IfIndex == index {
				position = i
				break
			}
		}
		if position < 0 {
			continue
		}
		_, address, prefix, err := decodeAddress(m)
		if err != nil {
			return nil, at("kernel.corroboration.address.decode", err)
		}
		s := &segments[position]
		s.LinkAddresses = append(s.LinkAddresses, address)
		if prefix != "" && !slices.Contains(s.Prefixes, prefix) {
			s.Prefixes = append(s.Prefixes, prefix)
		}
	}
	for i := range segments {
		s := &segments[i]
		s.LinkAddresses, err = uniqueSorted(s.LinkAddresses)
		if err != nil {
			return nil, at("kernel.corroboration.address.duplicate", err)
		}
		if len(s.LinkAddresses) > 64 {
			return nil, at("kernel.corroboration.address.count", nil)
		}
		sort.Strings(s.Prefixes)
		if len(s.Prefixes) == 0 || len(s.Prefixes) > 32 {
			return nil, at("kernel.corroboration.prefix.count", nil)
		}
		if stock {
			match, err := matchNativeIPv4Prefixes(s.Prefixes, nativeByInterface[s.Interface].prefixes)
			if err != nil || !match {
				return nil, at("kernel.corroboration.prefix.native-mismatch", err)
			}
		}
		if stock {
			v := nativeByInterface[s.Interface]
			prefix, err := netip.ParsePrefix(v.prefixes[0])
			if err != nil {
				return nil, at("kernel.corroboration.prefix.native-parse", err)
			}
			if !slices.Contains(s.LinkAddresses, v.fields["address"]+"/"+strconv.Itoa(prefix.Bits())) {
				return nil, at("kernel.corroboration.address.native-host-missing", nil)
			}
		}
	}
	for i, s := range segments {
		for j, other := range segments {
			if j <= i {
				continue
			}
			for _, left := range s.Prefixes {
				for _, right := range other.Prefixes {
					a, _ := netip.ParsePrefix(left)
					b, _ := netip.ParsePrefix(right)
					if a.Overlaps(b) {
						return nil, at("kernel.corroboration.prefix.overlap", nil)
					}
				}
			}
		}
	}
	sort.Slice(segments, func(i, j int) bool { return segments[i].ID < segments[j].ID })
	return segments, nil
}

// Closed comparison states are diagnostic only. Only Complete is a match.
type bridgeMatch uint8

const (
	bridgeMatchNoMAC bridgeMatch = iota
	bridgeMatchWrongKind
	bridgeMatchWrongLinkType
	bridgeMatchWrongPrefixes
	bridgeMatchWrongAddress
	bridgeMatchComplete
)

func matchNativeBridge(v nativeSegment, link kernelLink, frames []message) (bridgeMatch, error) {
	if link.MAC != v.mac {
		return bridgeMatchNoMAC, nil
	}
	if link.kind != "bridge" {
		return bridgeMatchWrongKind, nil
	}
	if link.linkType != 1 {
		return bridgeMatchWrongLinkType, nil
	}
	addresses, prefixes := []string{}, []string{}
	for _, m := range frames {
		if len(m.data) < 8 {
			return bridgeMatchNoMAC, at("kernel.corroboration.bridge.match.address-frame", nil)
		}
		if int(binary.NativeEndian.Uint32(m.data[4:8])) != link.IfIndex {
			continue
		}
		_, address, prefix, err := decodeAddress(m)
		if err != nil {
			return bridgeMatchNoMAC, at("kernel.corroboration.bridge.match.address-decode", err)
		}
		addresses = append(addresses, address)
		if prefix != "" && !slices.Contains(prefixes, prefix) {
			prefixes = append(prefixes, prefix)
		}
	}
	sort.Strings(prefixes)
	if len(v.prefixes) != 1 {
		return bridgeMatchNoMAC, at("kernel.corroboration.bridge.match.native-prefix-count", nil)
	}
	p, err := netip.ParsePrefix(v.prefixes[0])
	if err != nil {
		return bridgeMatchNoMAC, at("kernel.corroboration.bridge.match.native-prefix-parse", err)
	}
	match, err := matchNativeIPv4Prefixes(prefixes, v.prefixes)
	if err != nil {
		return bridgeMatchNoMAC, at("kernel.corroboration.bridge.match.prefix-parse", err)
	}
	if !match {
		return bridgeMatchWrongPrefixes, nil
	}
	if !slices.Contains(addresses, v.fields["address"]+"/"+strconv.Itoa(p.Bits())) {
		return bridgeMatchWrongAddress, nil
	}
	return bridgeMatchComplete, nil
}

// The reviewed NDM "show interface" shape corroborates its exact IPv4
// network/host, MAC and Bridge role. Its empty top-level IPv6 field is not an
// assertion that IPv6 is absent: the actual selected-interface detail exposes
// IPv6 addresses beneath that empty field. Kernel RTM_GETADDR supplies every
// actual address/prefix on the uniquely corroborated bridge. IPv6 remains in
// Segment.Prefixes/LinkAddresses and the original Review/fence comparison;
// it is never synthesized, discarded or used to choose a generic bridge.
func matchNativeIPv4Prefixes(observed, native []string) (bool, error) {
	if len(native) != 1 {
		return false, ErrUnknown
	}
	nativePrefix, err := netip.ParsePrefix(native[0])
	if err != nil || !nativePrefix.Addr().Is4() || nativePrefix != nativePrefix.Masked() || !lanPrefix(nativePrefix) {
		return false, ErrUnknown
	}
	var ipv4 []string
	for _, value := range observed {
		prefix, err := netip.ParsePrefix(value)
		if err != nil || prefix != prefix.Masked() || prefix.Addr().Zone() != "" || !lanPrefix(prefix) {
			return false, ErrUnknown
		}
		if prefix.Addr().Is4() {
			ipv4 = append(ipv4, value)
		}
	}
	return slices.Equal(ipv4, native), nil
}

func nativeMemberMatches(v nativeSegment, link kernelLink) bool {
	if !validMAC(v.mac) || strings.ToLower(v.mac) != link.MAC || v.global == "yes" || v.fields["public"] == "yes" {
		return false
	}
	// Actual stock fixture contains a shared MAC on its VLAN and an AP.
	// Kernel VLAN kind distinguishes that tuple; native labels are never
	// shortened or converted to interface names. Any remaining tie refuses.
	switch v.kind {
	case "Vlan":
		return link.kind == "vlan"
	case "AccessPoint", "Port", "GigabitEthernet", "XGigabitEthernet":
		return link.kind == ""
	default:
		return false
	}
}

// This private adapter represents the actual bounded RTM_GETNEIGH rows in the
// already accepted devices grammar. No executable, registry, DHCP/ARP cache,
// user runner or persisted fallback supplies a row. Manager is an ephemeral
// read-only aggregator; it neither loads nor creates a device registry.
type kernelNeighborRows map[string]map[bool][]byte

func (r kernelNeighborRows) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	if ctx.Err() != nil || name != "kernel-rtnetlink-neighbors" || len(args) != 5 || args[1] != "neigh" || args[2] != "show" || args[3] != "dev" || args[0] != "-4" && args[0] != "-6" {
		return nil, ErrUnknown
	}
	rows, ok := r[args[4]]
	if !ok {
		return nil, ErrUnknown
	}
	data, ok := rows[args[0] == "-6"]
	if !ok {
		return nil, ErrUnknown
	}
	return slices.Clone(data), nil
}
func bindDevices(ctx context.Context, segments []Segment, rows kernelNeighborRows) ([]Device, error) {
	ifaces := []string{}
	for _, s := range segments {
		ifaces = append(ifaces, s.Interface)
	}
	m := &devices.Manager{Runner: rows, IPCommand: "kernel-rtnetlink-neighbors"}
	observed, err := m.ObserveBindings(ctx, ifaces)
	if err != nil {
		return nil, err
	}
	out := make([]Device, 0, len(observed.Bindings))
	owners := map[string]bool{}
	for _, b := range observed.Bindings {
		var segment Segment
		for _, s := range segments {
			if s.Interface == b.Interface {
				segment = s
				break
			}
		}
		if segment.IfIndex == 0 {
			return nil, ErrUnknown
		}
		device := Device{ID: b.ID, MAC: b.MAC, Interface: b.Interface, IfIndex: segment.IfIndex, SegmentID: segment.ID, Addresses: []string{}, LinkLocalAddresses: []string{}}
		for _, a := range b.Addresses {
			address, err := netip.ParseAddr(a.Address)
			if err != nil {
				return nil, err
			}
			matches := 0
			for _, p := range segment.Prefixes {
				prefix, err := netip.ParsePrefix(p)
				if err != nil {
					return nil, err
				}
				if prefix.Contains(address) {
					matches++
				}
			}
			// Link-local mappings stay frozen for exact NUD comparison, but do
			// not become routable selected client sources.
			if address.IsLinkLocalUnicast() {
				device.LinkLocalAddresses = append(device.LinkLocalAddresses, a.Address)
				continue
			}
			if matches != 1 || owners[a.Address] {
				return nil, ErrUnknown
			}
			owners[a.Address] = true
			device.Addresses = append(device.Addresses, a.Address)
		}
		if len(device.Addresses) == 0 && len(device.LinkLocalAddresses) == 0 {
			continue
		}
		out = append(out, device)
	}
	return out, nil
}
