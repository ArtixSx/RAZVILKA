package physicalscope

import (
	"bytes"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"unicode/utf8"
)

type nativeSegment struct {
	id, name, osName, kind, global, security, link, state, connected, mac string
	prefixes                                                              []string
	members                                                               []string
	fields                                                                map[string]string
	index                                                                 uint32
}

// The accepted NC1812 command is structured text. Essential fields belong to
// the reviewed object column (17, or 18 for Port), never a nested port/link-group
// ID or MAC. The first direct ID fixes that column for this object. Repeated
// traits and unrelated metadata do not supply any role or attachment evidence.
func parseNDM(raw []byte) ([]nativeSegment, error) {
	if len(raw) == 0 || len(raw) > 1<<20 || bytes.IndexByte(raw, 0) >= 0 {
		return nil, ErrUnknown
	}
	envelope := []byte("\x1b[K")
	if bytes.HasPrefix(raw, envelope) || bytes.HasSuffix(raw, envelope) {
		if len(raw) < 6 || !bytes.HasPrefix(raw, envelope) || !bytes.HasSuffix(raw, envelope) {
			return nil, at("ndm.envelope", nil)
		}
		raw = raw[3 : len(raw)-3]
	}
	if !utf8.Valid(raw) || len(raw) == 0 || raw[len(raw)-1] != '\n' {
		return nil, at("ndm.text-shape", nil)
	}
	for i, b := range raw {
		if b == '\r' && i+1 < len(raw) && raw[i+1] == '\n' {
			continue
		}
		if b < 32 && b != '\n' || b == 127 {
			return nil, at("ndm.control-byte", nil)
		}
	}
	lines := strings.Split(string(raw), "\n")
	if len(lines) > 32768 {
		return nil, ErrUnknown
	}
	var out []nativeSegment
	var fields map[string]string
	var current nativeSegment
	bridge, ipv6 := false, false
	rootColumn := 0
	finish := func() error {
		if fields == nil {
			return nil
		}
		for _, key := range []string{"id", "index", "interface-name", "type"} {
			if fields[key] == "" {
				return at("ndm.required-"+key, nil)
			}
		}
		if !segmentID.MatchString(fields["id"]) || !segmentID.MatchString(current.name) {
			return at("ndm.native-id-shape", nil)
		}
		index, err := strconv.ParseUint(fields["index"], 10, 32)
		if err != nil || strconv.FormatUint(index, 10) != fields["index"] {
			return at("ndm.index-shape", nil)
		}
		current.index = uint32(index)
		current.id, current.osName, current.kind = fields["id"], fields["interface-name"], fields["type"]
		current.global, current.security = fields["global"], fields["security-level"]
		current.link, current.state, current.connected = fields["link"], fields["state"], fields["connected"]
		current.mac = fields["mac"]
		current.fields = fields
		out = append(out, current)
		if len(out) > 512 {
			return ErrUnknown
		}
		return nil
	}
	essential := map[string]bool{}
	for _, key := range []string{"id", "index", "interface-name", "type", "global", "public", "security-level", "link", "state", "connected", "mac", "address", "mask", "ipv6", "bridge"} {
		essential[key] = true
	}
	for _, line := range lines {
		line = strings.TrimSuffix(line, "\r")
		if strings.TrimSpace(line) == "" {
			continue
		}
		if strings.HasPrefix(line, "Interface, name = ") {
			if err := finish(); err != nil {
				return nil, err
			}
			name := strings.TrimPrefix(line, "Interface, name = ")
			if len(name) < 3 || name[0] != '"' || name[len(name)-1] != '"' || strings.ContainsAny(name[1:len(name)-1], "\"\\") {
				return nil, at("ndm.header-shape", nil)
			}
			current = nativeSegment{name: name[1 : len(name)-1]}
			fields, bridge, ipv6 = map[string]string{}, false, false
			rootColumn = 0
			continue
		}
		if fields == nil || len(line) > 8192 {
			return nil, at("ndm.line-bound", nil)
		}
		colon := strings.IndexByte(line, ':')
		if colon < 0 {
			return nil, at("ndm.field-shape", nil)
		}
		key, value := strings.TrimSpace(line[:colon]), strings.TrimSpace(line[colon+1:])
		if rootColumn == 0 {
			// Actual WifiMaster/Opkg records can begin with an unrelated
			// ap/uptime subtree. Its nested IDs cannot establish root scope.
			if key != "id" || colon != 17 && colon != 18 {
				continue
			}
			rootColumn = colon
		}
		if colon == rootColumn {
			bridge = key == "bridge"
			ipv6 = key == "ipv6"
			if essential[key] {
				if _, exists := fields[key]; exists {
					return nil, at("ndm.duplicate-"+key, nil)
				}
				fields[key] = value
			}
		} else if ipv6 {
			fields["ipv6-subtree"] = "unsupported"
		} else if bridge && strings.HasPrefix(key, "interface, link = ") {
			if (key != "interface, link = yes" && key != "interface, link = no") || !segmentID.MatchString(value) || slicesContains(current.members, value) {
				return nil, at("ndm.member-shape", nil)
			}
			current.members = append(current.members, value)
		}
	}
	if err := finish(); err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, ErrUnknown
	}
	ids, names := map[string]bool{}, map[string]bool{}
	for _, v := range out {
		if ids[v.id] || names[v.name] {
			return nil, at("ndm.duplicate-native-object", nil)
		}
		ids[v.id], names[v.name] = true, true
	}
	return out, nil
}
func validateNativeBridge(v nativeSegment) (nativeSegment, error) {
	if v.kind != "Bridge" {
		return nativeSegment{}, at("kernel.corroboration.native.bridge.kind", nil)
	}
	for _, key := range []string{"global", "security-level", "link", "state", "connected", "mac", "address", "mask", "ipv6", "bridge"} {
		if _, ok := v.fields[key]; !ok {
			// key comes only from the closed literal list above, never NDM.
			return nativeSegment{}, at("kernel.corroboration.native.bridge.required-"+key, nil)
		}
	}
	// The reviewed full "show interface" shape has an empty IPv6 field with
	// no subtree. That is not proof of IPv6 absence; kernel facts are retained
	// separately. A changed full-command dialect still requires review.
	if v.fields["ipv6"] != "" {
		return nativeSegment{}, at("kernel.corroboration.native.bridge.ipv6-value", nil)
	}
	if v.fields["ipv6-subtree"] != "" {
		return nativeSegment{}, at("kernel.corroboration.native.bridge.ipv6-subtree", nil)
	}
	if v.fields["bridge"] != "" {
		return nativeSegment{}, at("kernel.corroboration.native.bridge.value", nil)
	}
	if !segmentID.MatchString(v.osName) {
		return nativeSegment{}, at("kernel.corroboration.native.bridge.interface-label", nil)
	}
	address, err := netip.ParseAddr(v.fields["address"])
	mask := net.ParseIP(v.fields["mask"]).To4()
	if err != nil || !address.Is4() {
		return nativeSegment{}, at("kernel.corroboration.native.bridge.address", err)
	}
	if mask == nil {
		return nativeSegment{}, at("kernel.corroboration.native.bridge.mask", nil)
	}
	ones, bits := net.IPMask(mask).Size()
	if bits != 32 || ones <= 0 || ones > 32 {
		return nativeSegment{}, at("kernel.corroboration.native.bridge.mask-bits", nil)
	}
	prefix := netip.PrefixFrom(address, ones).Masked()
	if !lanPrefix(prefix) {
		return nativeSegment{}, at("kernel.corroboration.native.bridge.prefix", nil)
	}
	if !validMAC(v.mac) {
		return nativeSegment{}, at("kernel.corroboration.native.bridge.mac", nil)
	}
	if len(v.members) == 0 || len(v.members) > 64 {
		return nativeSegment{}, at("kernel.corroboration.native.bridge.member-count", nil)
	}
	v.mac = strings.ToLower(v.mac)
	v.prefixes = []string{prefix.String()}
	return v, nil
}
func slicesContains(s []string, value string) bool {
	for _, v := range s {
		if v == value {
			return true
		}
	}
	return false
}
func resolveNative(all []nativeSegment, selected string) (nativeSegment, error) {
	var result nativeSegment
	count := 0
	for _, v := range all {
		if v.id == selected || v.name == selected {
			result = v
			count++
		}
	}
	if count != 1 {
		return nativeSegment{}, ErrUnknown
	}
	return result, nil
}
func validMAC(value string) bool {
	m, err := net.ParseMAC(value)
	return err == nil && len(m) == 6 && m[0]&1 == 0 && m.String() != "00:00:00:00:00:00"
}
func lanPrefix(p netip.Prefix) bool {
	a := p.Addr()
	return p.IsValid() && p.Bits() > 0 && !a.Is4In6() && !a.IsUnspecified() && !a.IsLoopback() && !a.IsMulticast() && !a.IsLinkLocalUnicast()
}
