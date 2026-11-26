package physicalscope

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"net/netip"
	"slices"
	"strings"
	"testing"
)

// Test-only readback classes retain wire metadata, never raw client addresses,
// MACs, interface names or indices. They supply no physical Review or grant.
type neighborReadbackClass struct {
	DumpFamily     byte   `json:"dump_family"`
	Family         byte   `json:"family"`
	AddressLength  int    `json:"address_length"`
	AddressClass   string `json:"address_class"`
	State          uint16 `json:"state"`
	Flags          byte   `json:"flags"`
	Type           byte   `json:"type"`
	LLAddressLen   int    `json:"lladdr_length"`
	LLAddressClass string `json:"lladdr_class"`
	DecoderStage   string `json:"decoder_stage"`
}

type neighborReadbackCount struct {
	neighborReadbackClass
	Count int `json:"count"`
}

func classifyNeighborReadback(family byte, m message) neighborReadbackClass {
	c := neighborReadbackClass{DumpFamily: family, AddressClass: "unknown", LLAddressClass: "unknown"}
	_, _, err := decodeNeighbor(m)
	if err == nil {
		c.DecoderStage = "accepted"
	} else {
		var diagnostic *failure
		c.DecoderStage = "unknown"
		if errors.As(err, &diagnostic) {
			c.DecoderStage = diagnostic.stage
		}
	}
	if len(m.data) < 12 {
		return c
	}
	c.Family, c.State, c.Flags, c.Type = m.data[0], binary.NativeEndian.Uint16(m.data[8:10]), m.data[10], m.data[11]
	a, err := attrs(m.data[12:])
	if err != nil {
		return c
	}
	c.AddressLength, c.LLAddressLen = len(a[1]), len(a[2])
	address, ok := netip.AddrFromSlice(a[1])
	switch {
	case !ok:
		c.AddressClass = "malformed"
	case address.Is4In6():
		c.AddressClass = "mapped"
	case c.Family != 2 && c.Family != 10 || address.Is4() != (c.Family == 2):
		c.AddressClass = "family-mismatch"
	case address.IsUnspecified():
		c.AddressClass = "unspecified"
	case address.IsLoopback():
		c.AddressClass = "loopback"
	case address.IsMulticast():
		c.AddressClass = "multicast"
	case address.IsLinkLocalUnicast():
		c.AddressClass = "link-local"
	case address.IsGlobalUnicast():
		c.AddressClass = "unicast"
	default:
		c.AddressClass = "other"
	}
	switch {
	case len(a[2]) == 0:
		c.LLAddressClass = "absent"
	case len(a[2]) != 6:
		c.LLAddressClass = "malformed"
	case slices.Equal(a[2], []byte{0, 0, 0, 0, 0, 0}):
		c.LLAddressClass = "zero"
	case a[2][0]&1 != 0:
		c.LLAddressClass = "multicast"
	default:
		c.LLAddressClass = "unicast"
	}
	return c
}

func summarizeNeighborReadback(counts map[neighborReadbackClass]int) []neighborReadbackCount {
	out := make([]neighborReadbackCount, 0, len(counts))
	for c, count := range counts {
		out = append(out, neighborReadbackCount{c, count})
	}
	slices.SortFunc(out, func(a, b neighborReadbackCount) int {
		left, _ := json.Marshal(a.neighborReadbackClass)
		right, _ := json.Marshal(b.neighborReadbackClass)
		return strings.Compare(string(left), string(right))
	})
	return out
}

func TestPhysicalNeighborReadbackClassifiesRefusalWithoutExposingTuple(t *testing.T) {
	for _, tc := range []struct{ address, class string }{
		{"192.0.2.20", "unicast"}, {"fe80::20", "link-local"}, {"224.0.0.1", "multicast"}, {"ff02::1", "multicast"}, {"0.0.0.0", "unspecified"}, {"::", "unspecified"}, {"127.0.0.1", "loopback"}, {"::1", "loopback"}, {"::ffff:192.0.2.20", "mapped"},
	} {
		m := neighborFrame(9, tc.address, "02:00:00:00:00:03", 2)
		c := classifyNeighborReadback(m.data[0], m)
		if c.AddressClass != tc.class {
			t.Fatal("address class", tc.class, c)
		}
		raw, _ := json.Marshal(c)
		if strings.Contains(string(raw), tc.address) || strings.Contains(string(raw), "02:00:") || strings.Contains(string(raw), "ifindex") {
			t.Fatal("readback exposes raw tuple")
		}
	}
	m := neighborFrame(9, "192.0.2.20", "02:00:00:00:00:03", 2)
	m.data[0] = 10
	if c := classifyNeighborReadback(2, m); c.AddressClass != "family-mismatch" || c.DumpFamily != 2 || c.Family != 10 || c.AddressLength != 4 {
		t.Fatal("request/row family distinction lost", c)
	}
	m.data = append(m.data[:12:12], attr(1, []byte{1, 2, 3})...)
	if c := classifyNeighborReadback(10, m); c.AddressClass != "malformed" || c.AddressLength != 3 {
		t.Fatal("malformed address hidden", c)
	}
}
