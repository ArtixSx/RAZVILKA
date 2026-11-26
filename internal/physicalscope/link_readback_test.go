package physicalscope

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// Test-only comparisons against the first actual GETLINK dump. No link tuple,
// attribute payload, interface name/index, Review or admission escapes here.
type linkReadbackClass struct {
	Phase           string `json:"phase"`
	Kind            uint16 `json:"kind"`
	Role            string `json:"role"`
	Family          byte   `json:"family"`
	NetlinkFlags    uint16 `json:"netlink_flags"`
	InterfaceFlags  uint32 `json:"interface_flags"`
	ChangeMask      uint32 `json:"change_mask"`
	Decoder         string `json:"decoder"`
	ParsedFields    string `json:"parsed_fields"`
	AttributeIDs    string `json:"attribute_ids"`
	AttributeSizes  string `json:"attribute_sizes"`
	ReferenceSizes  string `json:"reference_attribute_sizes"`
	AttributeDelta  string `json:"attribute_delta"`
	AttributeClass  string `json:"attribute_change_class"`
	LinkInfoDelta   string `json:"link_info_delta"`
	InfoDataDelta   string `json:"info_data_delta"`
	SlaveDataDelta  string `json:"slave_data_delta"`
	AFSpecDelta     string `json:"af_spec_delta"`
	IPv6Delta       string `json:"ipv6_delta"`
	RuntimeDecision string `json:"runtime_decision"`
}

type linkReadbackCount struct {
	linkReadbackClass
	Count int `json:"count"`
}

func classifyLinkReadback(phase string, m message, baseline map[int]message, segments []Segment) linkReadbackClass {
	c := linkReadbackClass{Phase: phase, Kind: m.kind, NetlinkFlags: m.flags, Decoder: "refused", Role: "unknown", ParsedFields: "unavailable"}
	if err := checkNotifications([]message{m}, segments, nil); err != nil {
		c.RuntimeDecision = boundary("readback.notification", err).Error()
	} else {
		c.RuntimeDecision = "accepted"
	}
	if len(m.data) < 16 {
		return c
	}
	c.Family, c.InterfaceFlags, c.ChangeMask = m.data[0], binary.NativeEndian.Uint32(m.data[8:12]), binary.NativeEndian.Uint32(m.data[12:16])
	a, err := attrs(m.data[16:])
	if err != nil {
		return c
	}
	c.AttributeIDs = attributeIDs(a)
	c.AttributeSizes = attributeSizes(a)
	link, err := decodeLink(m)
	if err != nil {
		return c
	}
	c.Decoder = "accepted"
	c.Role = readbackLinkRole(link, segments)
	before, ok := baseline[link.IfIndex]
	if !ok {
		return c
	}
	original, err := decodeLink(before)
	if err != nil {
		return c
	}
	c.ParsedFields = linkFieldDelta(original.Link, link.Link)
	b, err := attrs(before.data[16:])
	if err != nil {
		return c
	}
	c.ReferenceSizes = attributeSizes(b)
	c.AttributeDelta, c.AttributeClass = attributeDelta(b, a)
	oldInfo, oldErr := attrs(b[18])
	newInfo, newErr := attrs(a[18])
	c.LinkInfoDelta = "opaque"
	if oldErr == nil && newErr == nil {
		c.LinkInfoDelta, _ = attributeDelta(oldInfo, newInfo)
		c.InfoDataDelta = nestedAttributeDelta(oldInfo[2], newInfo[2])
		c.SlaveDataDelta = nestedAttributeDelta(oldInfo[5], newInfo[5])
	}
	oldAF, oldErr := attrs(b[26])
	newAF, newErr := attrs(a[26])
	c.AFSpecDelta = "opaque"
	if oldErr == nil && newErr == nil {
		c.AFSpecDelta, _ = attributeDelta(oldAF, newAF)
		c.IPv6Delta = nestedAttributeDelta(oldAF[10], newAF[10])
	}
	return c
}

func readbackLinkRole(link kernelLink, segments []Segment) string {
	role := 0
	for _, s := range segments {
		if link.IfIndex == s.IfIndex {
			role |= 1
		}
		for _, m := range s.Members {
			if link.IfIndex == m.IfIndex {
				role |= 2
			}
			if m.Parent.Known && link.IfIndex == m.Parent.IfIndex {
				role |= 4
			}
		}
	}
	switch role {
	case 1:
		return "root"
	case 2:
		return "member"
	case 4:
		return "parent"
	case 0:
	default:
		return "multiple"
	}
	for _, s := range segments {
		if link.master == s.IfIndex {
			return "selected-master"
		}
		if link.Interface == s.Interface {
			return "tracked-name"
		}
		for _, m := range s.Members {
			if link.Interface == m.Interface || m.Parent.Known && link.Interface == m.Parent.Interface {
				return "tracked-name"
			}
			if link.ParentIfIndex == m.IfIndex || m.Parent.Known && link.ParentIfIndex == m.Parent.IfIndex {
				return "tracked-parent"
			}
		}
		if link.ParentIfIndex == s.IfIndex {
			return "tracked-parent"
		}
	}
	return "unrelated"
}

func linkFieldDelta(a, b Link) string {
	changes := []string{}
	for _, field := range []struct {
		name string
		same bool
	}{
		{"interface", a.Interface == b.Interface}, {"index", a.IfIndex == b.IfIndex},
		{"mac", a.MAC == b.MAC}, {"link-type", a.LinkType == b.LinkType},
		{"flags", a.Flags == b.Flags}, {"kind", a.Kind == b.Kind},
		{"master", a.MasterIfIndex == b.MasterIfIndex}, {"parent", a.ParentIfIndex == b.ParentIfIndex},
		{"foreign-parent", a.ForeignParent == b.ForeignParent}, {"slave-kind", a.SlaveKind == b.SlaveKind},
		{"bridge-state-known", a.BridgeStateKnown == b.BridgeStateKnown}, {"bridge-state", a.BridgePortState == b.BridgePortState},
		{"vlan", reflect.DeepEqual(a.VLAN, b.VLAN)},
	} {
		if !field.same {
			changes = append(changes, field.name)
		}
	}
	if len(changes) == 0 {
		return "same"
	}
	return strings.Join(changes, ",")
}

func attributeIDs(a map[uint16][]byte) string {
	ids := sortedAttributeIDs(a)
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		out = append(out, strconv.Itoa(int(id)))
	}
	return strings.Join(out, ",")
}

func sortedAttributeIDs(a map[uint16][]byte) []uint16 {
	ids := make([]uint16, 0, len(a))
	for id := range a {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	return ids
}

func attributeSizes(a map[uint16][]byte) string {
	out := []string{}
	for _, id := range sortedAttributeIDs(a) {
		out = append(out, strconv.Itoa(int(id))+":"+strconv.Itoa(len(a[id])))
	}
	return strings.Join(out, ",")
}

func attributeDelta(before, after map[uint16][]byte) (string, string) {
	ids := map[uint16][]byte{}
	for id := range before {
		ids[id] = nil
	}
	for id := range after {
		ids[id] = nil
	}
	changes := []string{}
	class := "stats-only" // IFLA_STATS=7 / IFLA_STATS64=23, Linux UAPI.
	for _, id := range sortedAttributeIDs(ids) {
		a, oldOK := before[id]
		b, newOK := after[id]
		if oldOK == newOK && bytes.Equal(a, b) {
			continue
		}
		change := "changed"
		if !oldOK {
			change = "added"
		} else if !newOK {
			change = "removed"
		}
		changes = append(changes, strconv.Itoa(int(id))+":"+change)
		if id != 7 && id != 23 {
			class = "other"
		}
	}
	if len(changes) == 0 {
		return "same", "none"
	}
	return strings.Join(changes, ","), class
}

func nestedAttributeDelta(before, after []byte) string {
	a, oldErr := attrs(before)
	b, newErr := attrs(after)
	if oldErr != nil || newErr != nil {
		return "opaque"
	}
	result, _ := attributeDelta(a, b)
	return result
}

func summarizeLinkReadback(counts map[linkReadbackClass]int) []linkReadbackCount {
	out := make([]linkReadbackCount, 0, len(counts))
	for c, count := range counts {
		out = append(out, linkReadbackCount{c, count})
	}
	slices.SortFunc(out, func(a, b linkReadbackCount) int {
		left, _ := json.Marshal(a.linkReadbackClass)
		right, _ := json.Marshal(b.linkReadbackClass)
		return strings.Compare(string(left), string(right))
	})
	return out
}

func TestPhysicalLinkReadbackDistinguishesStatsFromTopologyWithoutChangingFence(t *testing.T) {
	segments := []Segment{{Interface: "Home", IfIndex: 9, Members: []Link{{Interface: "eth0", IfIndex: 4}}}}
	base := linkFrame(9, "Home", "bridge", "02:00:00:00:00:01", 0)
	base.data = append(base.data, attr(7, make([]byte, 96))...)
	event := base
	event.data = slices.Clone(base.data)
	event.data[len(event.data)-1] = 1
	baseline := map[int]message{9: base}
	c := classifyLinkReadback("pass.before", event, baseline, segments)
	if c.Role != "root" || c.ParsedFields != "same" || c.AttributeDelta != "7:changed" || c.AttributeClass != "stats-only" || c.Decoder != "accepted" || !strings.Contains(c.RuntimeDecision, "notifications.link.tracked-index") {
		t.Fatal("statistics comparison adopted runtime admission", c)
	}
	for _, tc := range []struct {
		field string
		event message
	}{
		{"mac", linkFrame(9, "Home", "bridge", "02:00:00:00:00:09", 0)},
		{"interface", linkFrame(9, "private-name", "bridge", "02:00:00:00:00:01", 0)},
		{"master", linkFrame(9, "Home", "bridge", "02:00:00:00:00:01", 10)},
		{"kind", linkFrame(9, "Home", "tun", "02:00:00:00:00:01", 0)},
	} {
		c := classifyLinkReadback("pass.before", tc.event, baseline, segments)
		if !strings.Contains(c.ParsedFields, tc.field) || c.AttributeClass != "other" {
			t.Fatal("changed owned link field hidden", tc.field, c)
		}
	}
	changed := event
	changed.data = slices.Clone(event.data)
	binary.NativeEndian.PutUint32(changed.data[8:12], 0)
	if c := classifyLinkReadback("pass.before", changed, baseline, segments); c.ParsedFields != "flags" {
		t.Fatal("same statistics did not expose changed interface flags", c)
	}
	deleted := base
	deleted.kind = 17
	if c := classifyLinkReadback("pass.before", deleted, baseline, segments); c.Kind != 17 || c.ParsedFields != "same" || c.RuntimeDecision == "accepted" {
		t.Fatal("deletion/recreation became same-link refresh", c)
	}
	unknown := base
	unknown.data = append(slices.Clone(base.data), attr(250, []byte("private-input"))...)
	if c := classifyLinkReadback("pass.before", unknown, baseline, segments); c.AttributeDelta != "250:added" || c.AttributeClass != "other" {
		t.Fatal("unknown attribute was called statistics", c)
	}
	for _, m := range []message{event, changed, deleted, unknown, {kind: 16}} {
		raw, _ := json.Marshal(classifyLinkReadback("pass.before", m, baseline, segments))
		for _, private := range []string{"Home", "eth0", "02:00:", "192.0.", "private-input", "ifindex"} {
			if strings.Contains(string(raw), private) {
				t.Fatal("readback exposed raw link evidence")
			}
		}
	}
}

func TestPhysicalLinkReadbackRetainsNestedVLANAndAFDifferences(t *testing.T) {
	base := vlanFrame(39, "opaque-a", "02:00:00:00:00:05", 20, 9, 17, 0x8100, 5, 3)
	segments := []Segment{{Interface: "Home", IfIndex: 9, Members: []Link{{Interface: "opaque-a", IfIndex: 39, Parent: ParentLink{Known: true, Interface: "radio-a", IfIndex: 20}}}}}
	baseline := map[int]message{39: base}
	changed := vlanFrame(39, "opaque-a", "02:00:00:00:00:05", 20, 9, 18, 0x8100, 5, 3)
	c := classifyLinkReadback("pass.before", changed, baseline, segments)
	if c.Role != "member" || c.ParsedFields != "vlan" || c.LinkInfoDelta != "2:changed" || c.InfoDataDelta != "1:changed" || c.RuntimeDecision == "accepted" {
		t.Fatal("VLAN change became a statistical refresh", c)
	}
	changed = vlanFrame(39, "opaque-a", "02:00:00:00:00:05", 20, 9, 17, 0x8100, 5, 2)
	c = classifyLinkReadback("pass.before", changed, baseline, segments)
	if c.ParsedFields != "bridge-state" || c.SlaveDataDelta != "1:changed" {
		t.Fatal("bridge state notification hidden", c)
	}
	base.data = append(base.data, attr(26, attr(10, attr(3, integer(1))))...)
	changed = vlanFrame(39, "opaque-a", "02:00:00:00:00:05", 20, 9, 17, 0x8100, 5, 3)
	changed.data = append(changed.data, attr(26, attr(10, attr(3, integer(2))))...)
	c = classifyLinkReadback("pass.before", changed, map[int]message{39: base}, segments)
	if c.ParsedFields != "same" || c.AttributeDelta != "26:changed" || c.AFSpecDelta != "10:changed" || c.IPv6Delta != "3:changed" || c.AttributeClass != "other" {
		t.Fatal("AF-specific payload was erased or claimed as top-level statistics", c)
	}
	parent := linkFrame(20, "radio-a", "", "02:00:00:00:00:05", 0)
	if c := classifyLinkReadback("pass.before", parent, map[int]message{20: parent}, segments); c.Role != "parent" || c.ParsedFields != "same" || c.RuntimeDecision == "accepted" {
		t.Fatal("parent identity adopted as a refresh grant", c)
	}
}
