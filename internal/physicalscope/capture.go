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
			return nil, err
		}
		if _, ok := links[link.IfIndex]; ok {
			return nil, ErrUnknown
		}
		if _, ok := names[link.Interface]; ok {
			return nil, ErrUnknown
		}
		links[link.IfIndex], names[link.Interface] = link, link
	}
	wan := map[int]bool{}
	for _, m := range routeFrames {
		indices, err := decodeWAN(m)
		if err != nil {
			return nil, err
		}
		for _, index := range indices {
			wan[index] = true
		}
	}
	selected := append([]string{selection.HomeSegmentID}, selection.GuestSegmentIDs...)
	if len(selection.SegmentIDs) > 0 {
		if !stock {
			return nil, ErrUnknown
		} // Linux must explicitly identify Home.
		home := ""
		guests := []string{}
		for _, id := range selection.SegmentIDs {
			v, err := resolveNative(native, id)
			if err != nil {
				return nil, err
			}
			if v.kind != "Bridge" || v.global != "no" {
				return nil, ErrUnknown
			}
			switch v.security {
			case "private":
				if home != "" {
					return nil, ErrUnknown
				}
				home = id
			case "protected":
				guests = append(guests, id)
			default:
				return nil, ErrUnknown
			}
		}
		if home == "" {
			return nil, ErrUnknown
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
				return nil, err
			}
			resolved, err = validateNativeBridge(resolved)
			if err != nil {
				return nil, err
			}
			role := "private"
			if i > 0 {
				role = "protected"
			}
			if resolved.kind != "Bridge" || resolved.global != "no" || resolved.security != role || resolved.link != "up" || resolved.state != "up" || resolved.connected != "yes" {
				return nil, ErrUnknown
			}
		}
		link, ok := names[resolved.osName]
		if stock {
			count := 0
			for _, candidate := range links {
				match, err := matchNativeBridge(resolved, candidate, addressFrames)
				if err != nil {
					return nil, err
				}
				if match {
					link = candidate
					count++
				}
			}
			ok = count == 1
		}
		if !ok || !link.up || link.kind != "bridge" || link.linkType != 1 || !validMAC(link.MAC) || wan[link.IfIndex] || link.master != 0 || stock && resolved.mac != link.MAC {
			return nil, ErrUnknown
		}
		if _, ok := nativeByInterface[link.Interface]; ok {
			return nil, ErrUnknown
		}
		nativeByInterface[link.Interface] = resolved
		s := Segment{ID: resolved.id, NativeName: resolved.name, NativeInterfaceName: resolved.osName, NativeIndex: resolved.index, Interface: link.Interface, IfIndex: link.IfIndex, MAC: link.MAC, Home: i == 0, Guest: i > 0, Prefixes: []string{}, LinkAddresses: []string{}, Members: []Link{}}
		for _, member := range links {
			if member.master != link.IfIndex {
				continue
			}
			if wan[member.IfIndex] || member.linkType != 1 || !validMAC(member.MAC) || member.kind == "bridge" {
				return nil, ErrUnknown
			}
			s.Members = append(s.Members, member.Link)
		}
		if len(s.Members) == 0 || len(s.Members) > 64 {
			return nil, ErrUnknown
		}
		sort.Slice(s.Members, func(i, j int) bool { return s.Members[i].IfIndex < s.Members[j].IfIndex })
		if stock {
			matched := map[int]bool{}
			for _, member := range resolved.members {
				v, err := resolveNative(native, member)
				if err != nil {
					return nil, err
				}
				count := 0
				position := -1
				for j, m := range s.Members {
					if nativeMemberMatches(v, links[m.IfIndex]) {
						count++
						position = j
					}
				}
				if count != 1 || matched[s.Members[position].IfIndex] {
					return nil, ErrUnknown
				}
				m := &s.Members[position]
				matched[m.IfIndex] = true
				m.NativeID, m.NativeName, m.NativeInterfaceName, m.NativeType = v.id, v.name, v.osName, v.kind
			}
			if len(matched) != len(s.Members) {
				return nil, ErrUnknown
			}
		}
		segments = append(segments, s)
	}
	for _, m := range addressFrames {
		if len(m.data) < 8 {
			return nil, ErrUnknown
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
			return nil, err
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
		if err != nil || len(s.LinkAddresses) > 64 {
			return nil, ErrUnknown
		}
		sort.Strings(s.Prefixes)
		if len(s.Prefixes) == 0 || len(s.Prefixes) > 32 {
			return nil, ErrUnknown
		}
		if stock && !slices.Equal(s.Prefixes, nativeByInterface[s.Interface].prefixes) {
			return nil, ErrUnknown
		}
		if stock {
			v := nativeByInterface[s.Interface]
			prefix, err := netip.ParsePrefix(v.prefixes[0])
			if err != nil {
				return nil, err
			}
			if !slices.Contains(s.LinkAddresses, v.fields["address"]+"/"+strconv.Itoa(prefix.Bits())) {
				return nil, ErrUnknown
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
						return nil, ErrUnknown
					}
				}
			}
		}
	}
	sort.Slice(segments, func(i, j int) bool { return segments[i].ID < segments[j].ID })
	return segments, nil
}

func matchNativeBridge(v nativeSegment, link kernelLink, frames []message) (bool, error) {
	if link.kind != "bridge" || link.linkType != 1 || link.MAC != v.mac {
		return false, nil
	}
	addresses, prefixes := []string{}, []string{}
	for _, m := range frames {
		if len(m.data) < 8 {
			return false, ErrUnknown
		}
		if int(binary.NativeEndian.Uint32(m.data[4:8])) != link.IfIndex {
			continue
		}
		_, address, prefix, err := decodeAddress(m)
		if err != nil {
			return false, err
		}
		addresses = append(addresses, address)
		if prefix != "" && !slices.Contains(prefixes, prefix) {
			prefixes = append(prefixes, prefix)
		}
	}
	sort.Strings(prefixes)
	if len(v.prefixes) != 1 {
		return false, ErrUnknown
	}
	p, err := netip.ParsePrefix(v.prefixes[0])
	if err != nil {
		return false, err
	}
	return slices.Equal(prefixes, v.prefixes) && slices.Contains(addresses, v.fields["address"]+"/"+strconv.Itoa(p.Bits())), nil
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
