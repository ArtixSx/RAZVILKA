package physicalscope

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"net/netip"
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/netidentity"
)

func domainPolicyRuleModel(priority, table, mark uint32) message {
	d := make([]byte, 12)
	d[0], d[4], d[7] = 2, byte(table), 1
	d = append(d, attr(6, integer(priority))...)
	d = append(d, attr(15, integer(table))...)
	if mark != 0 {
		d = append(d, attr(10, integer(mark))...)
		d = append(d, attr(16, integer(0xff))...)
	}
	return message{kind: 32, flags: 2, data: d}
}

func domainPolicyInventoryModel() ([]message, []message, []message) {
	rules := []message{domainPolicyRuleModel(0, 255, 0), domainPolicyRuleModel(100, 10037, 42),
		domainPolicyRuleModel(200, 101, 1), domainPolicyRuleModel(300, 102, 2), domainPolicyRuleModel(400, 103, 3),
		domainPolicyRuleModel(32766, 254, 0), domainPolicyRuleModel(32767, 253, 0)}
	rules[1].data[2] = 24
	rules[1].data = append(rules[1].data, attr(2, []byte{192, 168, 71, 0})...)
	rules[1].data = append(rules[1].data, attr(3, []byte("br0\x00"))...)
	route := routeFrame(13)
	route.flags, route.data[4] = 2, 252
	route.data = append(route.data, attr(15, integer(10037))...)
	route.data = append(route.data, attr(5, []byte{192, 168, 72, 2})...)
	links := []message{linkFrame(12, "br0", "bridge", "02:00:00:00:00:01", 0),
		linkFrame(13, "wan0", "", "02:00:00:00:00:02", 0), linkFrame(14, "eth0", "", "02:00:00:00:00:03", 12)}
	for i := range links {
		links[i].flags = 2
	}
	return rules, []message{route}, links
}

func TestDomainIPv4PolicyInventoryRetainsSevenRulesAndUnknownSelectors(t *testing.T) {
	rules, routes, links := domainPolicyInventoryModel()
	unknown := attr(0x8055, []byte{1, 2, 3})
	rules[1].data = append(rules[1].data, unknown...)
	routes[0].data = append(routes[0].data, attr(8, []byte{4, 5, 6, 7})...) // Uninterpreted metrics remain.
	beforeRule := slices.Clone(rules[1].data)
	got, err := decodeDomainIPv4PolicyInventory(rules, routes, links)
	if err != nil || len(got.Rules) != 7 || len(got.Links) != 3 || len(got.Routes) != 1 {
		t.Fatalf("complete inventory lost: %+v %v", got, err)
	}
	rule := got.Rules[1]
	if rule.Table != 10037 || rule.Priority != 100 || rule.Mark != 42 || rule.Mask != 0xff ||
		!rule.MarkPresent || !rule.MaskPresent || rule.Input != "br0" || rule.Source.String() != "192.168.71.0/24" ||
		rule.Destination.String() != "0.0.0.0/0" || rule.Action != 1 {
		t.Fatalf("selectors lost: %+v", rule)
	}
	if !bytes.Equal(rule.Raw, beforeRule) || rule.Attributes[len(rule.Attributes)-1].Type != 0x8055 ||
		!bytes.Equal(rule.Attributes[len(rule.Attributes)-1].Value, []byte{1, 2, 3}) {
		t.Fatal("unknown selector or its type flags disappeared")
	}
	if got.Routes[0].Table != 10037 || got.Routes[0].OutputIndex != 13 || got.Routes[0].Gateway.String() != "192.168.72.2" ||
		got.Links[0].Kind != "bridge" || got.Links[2].MasterIndex != 12 {
		t.Fatal("table or bridge relationships disappeared")
	}
	for _, list := range [][]message{rules, routes, links} {
		for _, message := range list {
			clear(message.data)
		}
	}
	if !bytes.Equal(got.Rules[1].Raw, beforeRule) || binary.NativeEndian.Uint32(got.Rules[1].Attributes[0].Value) != 100 {
		t.Fatal("returned evidence aliases reusable kernel dump buffers")
	}
}

func TestDomainIPv4PolicyInventoryRefusesAmbiguousOrMalformedDump(t *testing.T) {
	for _, name := range []string{"duplicate-priority", "duplicate-flagged-selector", "bad-rule-family", "bad-rule-table", "missing-full-rule-table", "bad-route-table", "short-attribute", "unmasked-prefix", "duplicate-interface", "missing-links", "oversize-row", "interrupted-frame"} {
		t.Run(name, func(t *testing.T) {
			rules, routes, links := domainPolicyInventoryModel()
			switch name {
			case "duplicate-priority":
				rules[1].data = append(rules[1].data, attr(6, integer(101))...)
			case "duplicate-flagged-selector":
				rules[1].data = append(rules[1].data, attr(0x800a, integer(42))...)
			case "bad-rule-family":
				rules[0].data[0] = 10
			case "bad-rule-table":
				rules[1].data[4]++
			case "missing-full-rule-table":
				rules[1].data = rules[1].data[:12]
				rules[1].data[2], rules[1].data[4] = 0, 252
			case "bad-route-table":
				routes[0].data[4] = 254
			case "short-attribute":
				rules[0].data = append(rules[0].data, 3, 0, 44, 0)
			case "unmasked-prefix":
				rules[1].data[2] = 16
			case "duplicate-interface":
				links = append(links, links[0])
			case "missing-links":
				links = nil
			case "oversize-row":
				rules[0].data = make([]byte, 65537)
			case "interrupted-frame":
				rules[0].flags |= 0x10
			}
			got, err := decodeDomainIPv4PolicyInventory(rules, routes, links)
			if !errors.Is(err, ErrUnknown) || !reflect.DeepEqual(got, DomainIPv4PolicyInventory{}) {
				t.Fatalf("ambiguous inventory escaped: %+v %v", got, err)
			}
		})
	}
}

func TestDomainIPv4PolicyInventoryRetainsModernLargeRuleTable(t *testing.T) {
	rules, routes, links := domainPolicyInventoryModel()
	// Linux 6.8 fib_nl_fill_rule writes COMPAT252 for a large table. This
	// is a rule header, independently of the route header and GETROUTE reply.
	rules[1].data[4] = 252
	got, err := decodeDomainIPv4PolicyInventory(rules, routes, links)
	if err != nil || len(got.Rules) != 7 || got.Rules[1].Table != 10037 || got.Rules[1].Mark != 42 || got.Rules[1].Mask != 0xff {
		t.Fatalf("modern FRA_TABLE lost: %+v %v", got, err)
	}
	if got.Rules[1].Raw[4] != 252 {
		t.Fatal("original modern rule header was normalised")
	}
}

func TestDomainIPv4PolicySnapshotPreservesNamespaceAndCancellation(t *testing.T) {
	id := netidentity.Identity{Version: 1, Kind: netidentity.ProcNetInode, BootID: "12345678-1234-1234-1234-123456789abc", Inode: 92}
	for _, name := range []string{"valid", "wrong-namespace", "closing-failure", "cancelled-read", "duplicate-use", "no-deadline", "incomplete-dump"} {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			calls := 0
			current := func(c context.Context, use func(context.Context, netidentity.Identity) error) error {
				actual := id
				if name == "wrong-namespace" {
					actual.Inode++
				}
				err := use(c, actual)
				if name == "closing-failure" {
					return errors.Join(err, ErrUnknown)
				}
				if name == "duplicate-use" {
					return use(c, actual)
				}
				return err
			}
			read := func(c context.Context, kind uint16, family byte) ([]message, error) {
				calls++
				rules, routes, links := domainPolicyInventoryModel()
				if name == "cancelled-read" {
					cancel()
				}
				if name == "incomplete-dump" && kind == 26 {
					return nil, ErrUnknown
				}
				switch {
				case kind == 34 && family == 2:
					return rules, c.Err()
				case kind == 26 && family == 2:
					return routes, c.Err()
				case kind == 18 && family == 0:
					return links, c.Err()
				default:
					t.Fatalf("non-read ABI %d/%d", kind, family)
					return nil, ErrUnknown
				}
			}
			if name == "no-deadline" {
				ctx = context.Background()
			}
			got, err := readDomainIPv4PolicySnapshot(ctx, id, current, read)
			if name == "valid" {
				if err != nil || calls != 3 || len(got.Rules) != 7 {
					t.Fatalf("bounded whole inventory refused: %+v %v", got, err)
				}
			} else if !errors.Is(err, ErrUnknown) || !reflect.DeepEqual(got, DomainIPv4PolicyInventory{}) {
				t.Fatal("partial/stale observation escaped", err)
			}
			if name == "wrong-namespace" && calls != 0 || name == "no-deadline" && calls != 0 {
				t.Fatal("read started without its namespace and finite scope")
			}
		})
	}
}

func TestDomainIPv4PolicyLookupRetainsExplicitMarkAndActualTable(t *testing.T) {
	query := DomainIPv4PolicyLookupQuery{Source: netip.MustParseAddr("192.168.71.2"), Destination: netip.MustParseAddr("93.184.216.34"), IngressIndex: 12, Mark: 42}
	packet := domainIPv4PolicyRouteRequest(query, 19, 21)
	frames, err := messages(packet)
	if err != nil || len(frames) != 1 || frames[0].kind != 26 || frames[0].flags != 1 ||
		binary.NativeEndian.Uint32(frames[0].data[8:12]) != domainRouteLookupTable {
		t.Fatal("lookup became a dump/write")
	}
	a, err := attrs(frames[0].data[12:])
	if err != nil || len(a) != 4 || binary.NativeEndian.Uint32(a[16]) != 42 || binary.NativeEndian.Uint32(a[3]) != 12 ||
		!bytes.Equal(a[1], query.Destination.AsSlice()) || !bytes.Equal(a[2], query.Source.AsSlice()) {
		t.Fatal("lookup selector changed")
	}
	base, offsets := modelDomainIPv4Lookup(domainIPv4RouteQuery{query.Source, query.Destination, query.IngressIndex})
	base[20] = 252
	binary.NativeEndian.PutUint32(base[offsets[15]:], 10037)
	base = appendDomainIPv4ModelAttr(base, 16, integer(query.Mark))
	binary.NativeEndian.PutUint32(base[:4], uint32(len(base)))
	got, err := decodeDomainIPv4PolicyRouteReply(base, query, 19, 21, 100)
	if err != nil || got.Table != 10037 || got.Mark != 42 || got.IngressIndex != 12 || got.EgressIndex != 13 {
		t.Fatalf("actual alternate FIB table was lost: %+v %v", got, err)
	}
	oldKernel := slices.Clone(base)
	oldKernel[20] = byte(uint32(10037) & 0xff)
	legacy, err := decodeDomainIPv4PolicyRouteReply(oldKernel, query, 19, 21, 100)
	if err != nil || legacy.Table != 10037 || legacy.Mark != 42 {
		t.Fatal("Linux 4.9 rt_fill_info low-byte encoding refused", err)
	}
	for _, name := range []string{"changed-mark", "changed-source", "missing-mark", "flagged-mark", "foreign-sequence", "unknown-attribute", "duplicate-table", "conflicting-table", "truncation"} {
		t.Run(name, func(t *testing.T) {
			wire := slices.Clone(base)
			expected := query
			seq := uint32(19)
			switch name {
			case "changed-mark":
				expected.Mark++
			case "changed-source":
				expected.Source = netip.MustParseAddr("192.168.71.3")
			case "missing-mark":
				wire = wire[:len(wire)-8]
			case "flagged-mark":
				binary.NativeEndian.PutUint16(wire[len(wire)-6:], 16|0x4000)
			case "foreign-sequence":
				seq++
			case "unknown-attribute":
				wire = appendDomainIPv4ModelAttr(wire, 99, integer(1))
			case "duplicate-table":
				wire = appendDomainIPv4ModelAttr(wire, 15, integer(10037))
			case "conflicting-table":
				wire[20] = 254
			case "truncation":
				wire = wire[:len(wire)-1]
			}
			if name != "truncation" {
				binary.NativeEndian.PutUint32(wire[:4], uint32(len(wire)))
			}
			got, err := decodeDomainIPv4PolicyRouteReply(wire, expected, seq, 21, 100)
			if !errors.Is(err, ErrUnknown) || !reflect.DeepEqual(got, DomainIPv4PolicyLookup{}) {
				t.Fatal("ambiguous lookup escaped", err)
			}
		})
	}
}

func TestDomainIPv4PolicyLookupPreservesNamespaceAndCancellation(t *testing.T) {
	id := netidentity.Identity{Version: 1, Kind: netidentity.ProcNetInode, BootID: "12345678-1234-1234-1234-123456789abc", Inode: 92}
	query := DomainIPv4PolicyLookupQuery{Source: netip.MustParseAddr("192.168.71.2"), Destination: netip.MustParseAddr("93.184.216.34"), IngressIndex: 12, Mark: 42}
	observation := DomainIPv4PolicyLookup{Source: query.Source, Destination: query.Destination, IngressIndex: 12, EgressIndex: 13, Table: 10037, Mark: 42}
	for _, name := range []string{"valid", "wrong-namespace", "closing-failure", "cancelled-read", "duplicate-use", "no-deadline"} {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			deadline, _ := ctx.Deadline()
			calls := 0
			current := func(c context.Context, use func(context.Context, netidentity.Identity) error) error {
				actual := id
				if name == "wrong-namespace" {
					actual.Inode++
				}
				err := use(c, actual)
				if name == "closing-failure" {
					return errors.Join(err, ErrUnknown)
				}
				if name == "duplicate-use" {
					return use(c, actual)
				}
				return err
			}
			lookup := func(c context.Context, original DomainIPv4PolicyLookupQuery) (DomainIPv4PolicyLookup, error) {
				calls++
				limit, finite := c.Deadline()
				if original != query || !finite || limit.After(deadline) {
					t.Fatal("original selectors or caller's deadline changed")
				}
				if name == "cancelled-read" {
					cancel()
				}
				// A late result must still be discarded after cancellation or
				// failure to close the original namespace observation.
				return observation, nil
			}
			if name == "no-deadline" {
				ctx = context.Background()
			}
			got, err := readDomainIPv4PolicyRoute(ctx, id, query, current, lookup)
			if name == "valid" {
				if err != nil || calls != 1 || !reflect.DeepEqual(got, observation) {
					t.Fatalf("bounded marked lookup refused: %+v %v", got, err)
				}
			} else if !errors.Is(err, ErrUnknown) || !reflect.DeepEqual(got, DomainIPv4PolicyLookup{}) {
				t.Fatal("partial/stale marked lookup escaped", err)
			}
			if name == "wrong-namespace" && calls != 0 || name == "no-deadline" && calls != 0 {
				t.Fatal("lookup started without its namespace and finite scope")
			}
		})
	}
}
