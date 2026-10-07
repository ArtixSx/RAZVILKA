package physicalscope

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"slices"
	"strings"
	"testing"
)

func ndmField(key, value string) string { return fmt.Sprintf("%17s: %s\n", key, value) }
func ndmObject(name, id, iface, kind string) string {
	return "Interface, name = \"" + name + "\"\n" + ndmField("id", id) + ndmField("index", "0") + ndmField("interface-name", iface) + ndmField("type", kind)
}
func ndmHome() string {
	return ndmObject("Home", "Bridge0", "Home", "Bridge") + ndmField("traits", "Ethernet") + ndmField("traits", "Bridge") + ndmField("link", "up") + ndmField("connected", "yes") + ndmField("state", "up") + ndmField("address", "192.0.2.1") + ndmField("mask", "255.255.255.0") + ndmField("global", "no") + ndmField("security-level", "private") + ndmField("ipv6", "") + ndmField("mac", "02:00:00:00:00:01") + ndmField("bridge", "") + fmt.Sprintf("%33s: %s\n", "interface, link = yes", "GE0/0") + ndmField("summary", "ignored")
}
func ndmFixture() string {
	return ndmHome() + ndmObject("1", "GE0/0", "NativePort", "Port") + ndmField("mac", "02:00:00:00:00:02") + ndmObject("Wan", "GE1", "eth1", "GigabitEthernet") + ndmField("global", "yes")
}
func attr(kind uint16, raw []byte) []byte {
	n := 4 + len(raw)
	out := make([]byte, (n+3)&^3)
	binary.NativeEndian.PutUint16(out[:2], uint16(n))
	binary.NativeEndian.PutUint16(out[2:4], kind)
	copy(out[4:], raw)
	return out
}
func integer(v uint32) []byte {
	out := make([]byte, 4)
	binary.NativeEndian.PutUint32(out, v)
	return out
}
func linkFrame(index int, name, kind, mac string, master int) message {
	d := make([]byte, 16)
	binary.NativeEndian.PutUint16(d[2:4], 1)
	binary.NativeEndian.PutUint32(d[4:8], uint32(index))
	binary.NativeEndian.PutUint32(d[8:12], 1)
	d = append(d, attr(3, append([]byte(name), 0))...)
	parsed, _ := net.ParseMAC(mac)
	d = append(d, attr(1, parsed)...)
	if master != 0 {
		d = append(d, attr(10, integer(uint32(master)))...)
	}
	if kind != "" {
		d = append(d, attr(18, attr(1, append([]byte(kind), 0)))...)
	}
	return message{kind: 16, data: d}
}
func addressFrame(index int, prefix string) message {
	p := netip.MustParsePrefix(prefix)
	d := make([]byte, 8)
	d[0] = 2
	if p.Addr().Is6() {
		d[0] = 10
	}
	d[1] = byte(p.Bits())
	binary.NativeEndian.PutUint32(d[4:8], uint32(index))
	d = append(d, attr(1, p.Addr().AsSlice())...)
	return message{kind: 20, data: d}
}
func neighborFrame(index int, addr, mac string, state uint16) message {
	a := netip.MustParseAddr(addr)
	d := make([]byte, 12)
	d[0] = 2
	if a.Is6() {
		d[0] = 10
	}
	binary.NativeEndian.PutUint32(d[4:8], uint32(index))
	binary.NativeEndian.PutUint16(d[8:10], state)
	d[11] = 1
	d = append(d, attr(1, a.AsSlice())...)
	parsed, _ := net.ParseMAC(mac)
	if len(parsed) > 0 {
		d = append(d, attr(2, parsed)...)
	}
	return message{kind: 28, data: d}
}
func routeFrame(index int) message {
	d := make([]byte, 12)
	d[0] = 2
	d[4] = 254
	d[7] = 1
	d = append(d, attr(4, integer(uint32(index)))...)
	return message{kind: 24, data: d}
}
func kernelFixture() ([]message, []message, []message) {
	links := []message{linkFrame(9, "Home", "bridge", "02:00:00:00:00:01", 0), linkFrame(4, "eth0", "", "02:00:00:00:00:02", 9), linkFrame(5, "eth1", "", "02:00:00:00:00:04", 0)}
	addresses := []message{addressFrame(9, "192.0.2.1/24"), addressFrame(9, "fe80::1/64")}
	return links, addresses, []message{routeFrame(5)}
}
func TestPhysicalNDMActualTextShapeAndNestedFields(t *testing.T) {
	raw := ndmFixture()
	nested := fmt.Sprintf("%22s: %s\n", "id", "Foreign0") + fmt.Sprintf("%22s: %s\n", "global", "yes") + fmt.Sprintf("%22s: %s\n", "mac", "02:00:00:00:00:09")
	raw = strings.Replace(raw, ndmField("summary", "ignored"), ndmField("summary", "ignored")+nested, 1)
	all, err := parseNDM([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	v, err := resolveNative(all, "Home")
	if err != nil {
		t.Fatal(err)
	}
	v, err = validateNativeBridge(v)
	if err != nil || v.id != "Bridge0" || v.osName != "Home" || v.index != 0 || v.global != "no" || v.mac != "02:00:00:00:00:01" || !slices.Equal(v.prefixes, []string{"192.0.2.0/24"}) {
		t.Fatalf("native fields shadowed: %v", err)
	}
	for name, bad := range map[string]string{
		"unpaired envelope":   "\x1b[K" + raw,
		"embedded control":    strings.Replace(raw, "Home", "Home\x1b[K", 1),
		"duplicate key":       strings.Replace(raw, ndmField("global", "no"), ndmField("global", "no")+ndmField("global", "yes"), 1),
		"missing direct ID":   strings.Replace(raw, ndmField("id", "Bridge0"), fmt.Sprintf("%22s: %s\n", "id", "Bridge0"), 1),
		"duplicate native ID": raw + ndmObject("Other", "Bridge0", "Home", "Bridge"),
		"trailing prompt":     raw + "prompt>\n",
		"JSON assumption":     "{\"Home\":true}",
		"unknown IPv6":        strings.Replace(raw, ndmField("ipv6", ""), ndmField("ipv6", "enabled"), 1),
		"mask gap":            strings.Replace(raw, "255.255.255.0", "255.255.0.255", 1),
		"duplicate member":    strings.Replace(raw, ndmField("summary", "ignored"), fmt.Sprintf("%33s: %s\n", "interface, link = yes", "GE0/0")+ndmField("summary", "ignored"), 1),
	} {
		t.Run(name, func(t *testing.T) {
			all, err := parseNDM([]byte(bad))
			if err == nil {
				v, err = resolveNative(all, "Home")
				if err == nil {
					_, err = validateNativeBridge(v)
				}
			}
			if err == nil {
				t.Fatal("malformed selected native facts accepted")
			}
		})
	}
}
func TestPhysicalCorroboratesStockAndKernel(t *testing.T) {
	native, err := parseNDM([]byte(ndmFixture()))
	if err != nil {
		t.Fatal(err)
	}
	links, addresses, routes := kernelFixture()
	for _, selection := range []Selection{{HomeSegmentID: "Home"}, {SegmentIDs: []string{"Bridge0"}}} {
		segments, err := assembleSegments(selection, native, true, links, addresses, routes)
		if err != nil {
			t.Fatal(err)
		}
		if len(segments) != 1 || segments[0].ID != "Bridge0" || segments[0].IfIndex != 9 || segments[0].NativeIndex != 0 || !segments[0].Home || len(segments[0].Members) != 1 || len(segments[0].LinkAddresses) != 2 {
			t.Fatal("incomplete physical binding")
		}
	}
	// Native interface-name is a label. The actual kernel name may differ.
	actualLinks := slices.Clone(links)
	actualLinks[0] = linkFrame(9, "br0", "bridge", "02:00:00:00:00:01", 0)
	actual, err := assembleSegments(Selection{SegmentIDs: []string{"Home"}}, native, true, actualLinks, addresses, routes)
	if err != nil || actual[0].Interface != "br0" || actual[0].NativeInterfaceName != "Home" {
		t.Fatal("native label treated as OS name", err)
	}
	for name, change := range map[string]func(*[]message, *[]message, *[]message, *[]nativeSegment){
		"not bridge": func(l, a, r *[]message, n *[]nativeSegment) {
			(*l)[0] = linkFrame(9, "Home", "tun", "02:00:00:00:00:01", 0)
		},
		"MAC mismatch": func(l, a, r *[]message, n *[]nativeSegment) {
			(*l)[0] = linkFrame(9, "Home", "bridge", "02:00:00:00:00:09", 0)
		},
		"no members": func(l, a, r *[]message, n *[]nativeSegment) { *l = append((*l)[:1], (*l)[2:]...) },
		"foreign member": func(l, a, r *[]message, n *[]nativeSegment) {
			(*l)[1] = linkFrame(4, "foreign0", "", "02:00:00:00:00:09", 9)
		},
		"bridge is WAN":     func(l, a, r *[]message, n *[]nativeSegment) { *r = append(*r, routeFrame(9)) },
		"member is WAN":     func(l, a, r *[]message, n *[]nativeSegment) { *r = append(*r, routeFrame(4)) },
		"prefix mismatch":   func(l, a, r *[]message, n *[]nativeSegment) { (*a)[0] = addressFrame(9, "192.0.3.1/24") },
		"host mismatch":     func(l, a, r *[]message, n *[]nativeSegment) { (*a)[0] = addressFrame(9, "192.0.2.2/24") },
		"unexpected v6 LAN": func(l, a, r *[]message, n *[]nativeSegment) { *a = append(*a, addressFrame(9, "2001:db8::1/64")) },
		"public role":       func(l, a, r *[]message, n *[]nativeSegment) { (*n)[0].global = "yes" },
		"protected Home":    func(l, a, r *[]message, n *[]nativeSegment) { (*n)[0].security = "protected" },
		"duplicate index":   func(l, a, r *[]message, n *[]nativeSegment) { *l = append(*l, (*l)[0]) },
	} {
		t.Run(name, func(t *testing.T) {
			l, a, r := kernelFixture()
			n, err := parseNDM([]byte(ndmFixture()))
			if err != nil {
				t.Fatal(err)
			}
			change(&l, &a, &r, &n)
			if _, err := assembleSegments(Selection{HomeSegmentID: "Home"}, n, true, l, a, r); err == nil {
				t.Fatal("uncorroborated physical segment accepted")
			}
		})
	}
}

// Optional Root-provided fixture read, never a runtime producer or platform
// acceptance. It reports no addresses, MACs, process arguments or raw text.
func TestPhysicalNDMReadOnlyFixture(t *testing.T) {
	path := os.Getenv("RAZVILKA_PHYSICAL_NDM_FIXTURE")
	if path == "" {
		t.Skip("optional private Root-provided structured text fixture")
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, (1<<20)+1))
	if err != nil {
		t.Fatal(err)
	}
	native, err := parseNDM(raw)
	if err != nil {
		t.Fatal("bounded actual text shape", err)
	}
	v, err := resolveNative(native, "Home")
	if err != nil {
		t.Fatal("native selected object", err)
	}
	v, err = validateNativeBridge(v)
	if err != nil {
		t.Fatal("native selected bridge shape", err)
	}
	for _, id := range v.members {
		member, err := resolveNative(native, id)
		if err != nil || !validMAC(member.mac) {
			t.Fatal("native member binding unavailable")
		}
	}
	t.Logf("native_objects=%d home_members=%d text_shape_verified=true", len(native), len(v.members))
}
func TestPhysicalLinuxRequiresExplicitHomeAndSupportsBothFamilies(t *testing.T) {
	l, a, r := kernelFixture()
	a = append(a, addressFrame(9, "2001:db8::1/64"))
	segments, err := assembleSegments(Selection{HomeSegmentID: "Home"}, nil, false, l, a, r)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(segments[0].Prefixes, []string{"192.0.2.0/24", "2001:db8::/64"}) {
		t.Fatal("v6 prefix lost")
	}
	if _, err := assembleSegments(Selection{SegmentIDs: []string{"Home"}}, nil, false, l, a, r); err == nil {
		t.Fatal("Linux autoHome")
	}
}
func TestPhysicalKernelNeighborsUseExistingStrictAggregator(t *testing.T) {
	l, a, r := kernelFixture()
	a = append(a, addressFrame(9, "2001:db8::1/64"))
	segments, err := assembleSegments(Selection{HomeSegmentID: "Home"}, nil, false, l, a, r)
	if err != nil {
		t.Fatal(err)
	}
	rows := kernelNeighborRows{"Home": {false: {}, true: {}}}
	for _, m := range []message{neighborFrame(9, "192.0.2.20", "02:00:00:00:00:03", 2), neighborFrame(9, "2001:db8::20", "02:00:00:00:00:03", 4), neighborFrame(9, "fe80::20", "02:00:00:00:00:03", 4)} {
		_, row, err := decodeNeighbor(m)
		if err != nil {
			t.Fatal(err)
		}
		v6 := m.data[0] == 10
		rows["Home"][v6] = append(rows["Home"][v6], []byte(row)...)
	}
	devices, err := bindDevices(context.Background(), segments, rows)
	if err != nil || len(devices) != 1 || len(devices[0].Addresses) != 2 || len(devices[0].LinkLocalAddresses) != 1 || devices[0].IfIndex != 9 || devices[0].SegmentID != "Home" {
		t.Fatalf("actual attachment lost: %v", err)
	}
	rows["Home"][false] = append(rows["Home"][false], []byte("192.0.2.20 lladdr 02:00:00:00:00:04 REACHABLE\n")...)
	if _, err := bindDevices(context.Background(), segments, rows); err == nil {
		t.Fatal("duplicate address owner accepted")
	}
	rows["Home"][false] = []byte("198.51.100.20 lladdr 02:00:00:00:00:03 REACHABLE\n")
	if _, err := bindDevices(context.Background(), segments, rows); err == nil {
		t.Fatal("foreign prefix device accepted")
	}
}

func TestPhysicalSelectedSetResolvesActualHomeAndExplicitGuests(t *testing.T) {
	raw := ndmFixture()
	guest := strings.NewReplacer("Home", "iot", "Bridge0", "Bridge1", "192.0.2.1", "192.0.3.1", "private", "protected", "02:00:00:00:00:01", "02:00:00:00:00:05", "GE0/0", "GE0/1").Replace(ndmHome())
	raw += guest + ndmObject("2", "GE0/1", "NativeGuestPort", "Port") + ndmField("mac", "02:00:00:00:00:06")
	native, err := parseNDM([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	l, a, r := kernelFixture()
	l = append(l, linkFrame(10, "brguest", "bridge", "02:00:00:00:00:05", 0), linkFrame(6, "eth2", "", "02:00:00:00:00:06", 10))
	a = append(a, addressFrame(10, "192.0.3.1/24"))
	segments, err := assembleSegments(Selection{SegmentIDs: []string{"iot", "Home"}}, native, true, l, a, r)
	if err != nil || len(segments) != 2 || !segments[0].Home || !segments[1].Guest || segments[1].Interface != "brguest" {
		t.Fatal("selected set lost actual native roles", err)
	}
	for _, ids := range [][]string{{"iot"}, {"Wan"}, {"Home", "Bridge0"}, {"Home", "unknown"}} {
		if _, err := assembleSegments(Selection{SegmentIDs: ids}, native, true, l, a, r); err == nil {
			t.Fatal("no Home/ambiguous/unknown/public selection accepted")
		}
	}
	// Two different actual private bridges cannot silently choose one Home.
	native[3].security = "private"
	if _, err := assembleSegments(Selection{SegmentIDs: []string{"Home", "iot"}}, native, true, l, a, r); err == nil {
		t.Fatal("multiple private bridges chose Home")
	}
}
func TestPhysicalNativeMemberSharedMACRequiresUnambiguousKernelKind(t *testing.T) {
	l, a, r := kernelFixture()
	mac := "02:00:00:00:00:02"
	l[1] = linkFrame(4, "eth0.1", "vlan", mac, 9)
	l = append(l, linkFrame(6, "wlan0", "", mac, 9))
	raw := strings.Replace(ndmHome(), ndmField("summary", "ignored"), fmt.Sprintf("%33s: %s\n", "interface, link = yes", "Wifi0/AP0")+ndmField("summary", "ignored"), 1)
	raw += ndmObject("Vlan1", "GE0/0", "GigabitEthernet0/Vlan1", "Vlan") + ndmField("mac", mac) + ndmObject("AccessPoint", "Wifi0/AP0", "AccessPoint", "AccessPoint") + ndmField("mac", mac)
	native, err := parseNDM([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	s, err := assembleSegments(Selection{HomeSegmentID: "Home"}, native, true, l, a, r)
	if err != nil || len(s[0].Members) != 2 || s[0].Members[0].NativeType != "Vlan" || s[0].Members[1].NativeType != "AccessPoint" {
		t.Fatal("actual shared-MAC tuple lost kind binding", err)
	}
	l[1] = linkFrame(4, "eth0", "", mac, 9)
	if _, err := assembleSegments(Selection{HomeSegmentID: "Home"}, native, true, l, a, r); err == nil {
		t.Fatal("ambiguous same-class MAC attachment accepted")
	}
}
