package physicalscope

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net/netip"
	"slices"
	"testing"
)

func TestDomainIPv4RouteLookupRequestIsExact(t *testing.T) {
	client := netip.MustParseAddr("192.168.71.2")
	destination := netip.MustParseAddr("93.184.216.34")
	for _, ingress := range []int{0, 12} {
		query := domainIPv4RouteQuery{client, destination, ingress}
		packet := domainIPv4RouteRequest(query, 19, 21)
		framed, err := messages(packet)
		if err != nil || len(framed) != 1 {
			t.Fatalf("request framing: %v", err)
		}
		got := framed[0]
		attributes, err := attrs(got.data[12:])
		if err != nil {
			t.Fatal(err)
		}
		if got.kind != domainRouteGet || got.flags != 1 || got.seq != 19 || got.pid != 21 ||
			!bytes.Equal(got.data[:8], []byte{2, 32, 32, 0, 0, 0, 0, 0}) ||
			binary.NativeEndian.Uint32(got.data[8:12]) != domainRouteLookupTable ||
			!bytes.Equal(attributes[domainRouteSource], client.AsSlice()) ||
			!bytes.Equal(attributes[domainRouteDestination], destination.AsSlice()) {
			t.Fatalf("request widened or changed: %+v", got)
		}
		iif, err := u32(attributes, domainRouteInput)
		if err != nil || ingress == 0 && (len(attributes) != 2 || attributes[domainRouteInput] != nil) ||
			ingress != 0 && (len(attributes) != 3 || iif != uint32(ingress)) {
			t.Fatalf("mixed input with output semantics: ingress=%d attributes=%v err=%v", ingress, attributes, err)
		}
	}
}

func TestDomainIPv4RouteLookupReplyRefusesAmbiguity(t *testing.T) {
	forwarded := domainIPv4RouteQuery{netip.MustParseAddr("192.168.71.2"), netip.MustParseAddr("93.184.216.34"), 12}
	local := domainIPv4RouteQuery{netip.MustParseAddr("192.168.72.1"), forwarded.destination, 0}
	for _, query := range []domainIPv4RouteQuery{forwarded, local} {
		wire, fields := modelDomainIPv4Lookup(query)
		o, err := decodeDomainIPv4RouteReply(wire, query, 19, 21, 100)
		if err != nil || o.Source != query.source || o.Destination != query.destination ||
			o.IngressIndex != query.ingress || o.EgressIndex != 13 || o.Gateway.String() != "192.168.72.2" {
			t.Fatalf("known route refused: %+v, %v", o, err)
		}
		p, err := decodeDomainIPv4RouteReply(wire, query, 20, 21, 100)
		if p != (DomainIPv4RouteLookup{}) || !errors.Is(err, ErrUnknown) {
			t.Fatal("wrong sequence returned a route")
		}
		if query.ingress == 0 {
			if _, err := decodeDomainIPv4RouteReply(wire, query, 19, 21, 101); !errors.Is(err, ErrUnknown) {
				t.Fatal("conflicting local UID accepted")
			}
		}
		for _, change := range []string{"wrong-port", "wrong-message-kind", "multipart", "duplicate-message", "header-table", "attribute-table",
			"wrong-type", "marked", "duplicate-source", "missing-source", "different-source", "different-destination", "missing-kind",
			"egress-zero", "ingress-confusion", "cache-expiry", "cache-error", "invalid-gateway", "truncated"} {
			t.Run(change, func(t *testing.T) {
				copy := slices.Clone(wire)
				withAttr := func(kind uint16, value uint32) {
					copy = appendDomainIPv4ModelAttr(copy, kind, binary.NativeEndian.AppendUint32(nil, value))
					binary.NativeEndian.PutUint32(copy[:4], uint32(len(copy)))
				}
				switch change {
				case "wrong-port":
					binary.NativeEndian.PutUint32(copy[12:16], 22)
				case "wrong-message-kind":
					binary.NativeEndian.PutUint16(copy[4:6], 2)
				case "multipart":
					binary.NativeEndian.PutUint16(copy[6:8], 2)
				case "duplicate-message":
					copy = append(copy, wire...)
				case "header-table":
					copy[20] = 97
				case "attribute-table":
					binary.NativeEndian.PutUint32(copy[fields[domainRouteTable]:], 97)
				case "wrong-type":
					copy[23] = 2
				case "marked":
					withAttr(16, 1)
				case "duplicate-source":
					withAttr(domainRouteSource, 1)
				case "missing-source":
					binary.NativeEndian.PutUint16(copy[fields[domainRouteSource]-2:], 0)
				case "different-source":
					copy[fields[domainRouteSource]] = 100
				case "different-destination":
					copy[fields[domainRouteDestination]] = 100
				case "missing-kind":
					binary.NativeEndian.PutUint16(copy[fields[domainRouteTable]-2:], domainRouteTable|0x8000)
				case "egress-zero":
					binary.NativeEndian.PutUint32(copy[fields[domainRouteOutput]:], 0)
				case "ingress-confusion":
					if query.ingress == 0 {
						withAttr(domainRouteInput, 12)
					} else {
						binary.NativeEndian.PutUint32(copy[fields[domainRouteInput]:], 13)
					}
				case "cache-expiry":
					binary.NativeEndian.PutUint32(copy[fields[domainRouteCache]+8:], 1)
				case "cache-error":
					binary.NativeEndian.PutUint32(copy[fields[domainRouteCache]+12:], 1)
				case "invalid-gateway":
					copy[fields[domainRouteGateway]] = 127
				case "truncated":
					copy = copy[:len(copy)-1]
				}
				result, err := decodeDomainIPv4RouteReply(copy, query, 19, 21, 100)
				if result != (DomainIPv4RouteLookup{}) || !errors.Is(err, ErrUnknown) {
					t.Fatalf("ambiguous reply accepted: %+v, %v", result, err)
				}
			})
		}
	}
}

func modelDomainIPv4Lookup(query domainIPv4RouteQuery) ([]byte, map[uint16]int) {
	frame := make([]byte, 28)
	binary.NativeEndian.PutUint16(frame[4:6], domainRouteReply)
	binary.NativeEndian.PutUint32(frame[8:12], 19)
	binary.NativeEndian.PutUint32(frame[12:16], 21)
	frame[16], frame[17], frame[18], frame[20], frame[23] = 2, 32, 32, domainRouteMainTable, 1
	binary.NativeEndian.PutUint32(frame[24:28], domainRouteCloned)
	offsets := map[uint16]int{}
	appendAttr := func(kind uint16, value []byte) {
		offsets[kind] = len(frame) + 4
		frame = appendDomainIPv4ModelAttr(frame, kind, value)
	}
	appendAttr(domainRouteDestination, query.destination.AsSlice())
	appendAttr(domainRouteSource, query.source.AsSlice())
	appendAttr(domainRouteOutput, binary.NativeEndian.AppendUint32(nil, 13))
	appendAttr(domainRouteGateway, []byte{192, 168, 72, 2})
	appendAttr(domainRouteTable, binary.NativeEndian.AppendUint32(nil, domainRouteMainTable))
	appendAttr(domainRouteCache, make([]byte, 32))
	if query.ingress != 0 {
		appendAttr(domainRouteInput, binary.NativeEndian.AppendUint32(nil, uint32(query.ingress)))
	} else {
		appendAttr(domainRouteUID, binary.NativeEndian.AppendUint32(nil, 100))
	}
	binary.NativeEndian.PutUint32(frame[:4], uint32(len(frame)))
	return frame, offsets
}

func appendDomainIPv4ModelAttr(frame []byte, kind uint16, value []byte) []byte {
	frame = binary.NativeEndian.AppendUint16(frame, uint16(len(value)+4))
	frame = binary.NativeEndian.AppendUint16(frame, kind)
	return append(frame, value...)
}
