package dataplane

import (
	"encoding/binary"
	"net/netip"
	"reflect"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/dnscontrol"
)

// Entirely socket-free wire models. Production native transport is NEVER run.
func syntheticCTModelAttr(kind uint16, data []byte) []byte {
	b := make([]byte, (4+len(data)+3)&^3)
	binary.NativeEndian.PutUint16(b, uint16(4+len(data)))
	binary.NativeEndian.PutUint16(b[2:], kind)
	copy(b[4:], data)
	return b
}
func syntheticCTModelBE(value uint64, size int) []byte {
	b := make([]byte, size)
	switch size {
	case 2:
		binary.BigEndian.PutUint16(b, uint16(value))
	case 4:
		binary.BigEndian.PutUint32(b, uint32(value))
	case 8:
		binary.BigEndian.PutUint64(b, value)
	}
	return b
}
func syntheticCTModelTuple(r syntheticCTTuple) []byte {
	src, dst := r.Source.As4(), r.Destination.As4()
	ip := append(syntheticCTModelAttr(1, src[:]), syntheticCTModelAttr(2, dst[:])...)
	proto := syntheticCTModelAttr(1, []byte{r.Protocol})
	if r.Protocol == 6 || r.Protocol == 17 {
		proto = append(proto, syntheticCTModelAttr(2, syntheticCTModelBE(uint64(r.SourcePort), 2))...)
		proto = append(proto, syntheticCTModelAttr(3, syntheticCTModelBE(uint64(r.DestinationPort), 2))...)
	}
	out := append(syntheticCTModelAttr(0x8001, ip), syntheticCTModelAttr(0x8002, proto)...)
	if r.Zone != 0 {
		out = append(out, syntheticCTModelAttr(3, syntheticCTModelBE(uint64(r.Zone), 2))...)
	}
	return out
}
func syntheticCTModelBody(r syntheticCTRow, timeout uint32) []byte {
	out := []byte{2, 0, 0, 0}
	out = append(out, syntheticCTModelAttr(0x8001, syntheticCTModelTuple(r.Original))...)
	out = append(out, syntheticCTModelAttr(0x8002, syntheticCTModelTuple(r.Reply))...)
	out = append(out, syntheticCTModelAttr(3, syntheticCTModelBE(uint64(r.Status), 4))...)
	out = append(out, syntheticCTModelAttr(12, syntheticCTModelBE(uint64(r.ID), 4))...)
	out = append(out, syntheticCTModelAttr(7, syntheticCTModelBE(uint64(timeout), 4))...)
	if r.MarkPresent {
		out = append(out, syntheticCTModelAttr(8, syntheticCTModelBE(uint64(r.Mark), 4))...)
	}
	if r.Zone != 0 {
		out = append(out, syntheticCTModelAttr(18, syntheticCTModelBE(uint64(r.Zone), 2))...)
	}
	if r.BirthPresent {
		out = append(out, syntheticCTModelAttr(0x8014, syntheticCTModelAttr(1, syntheticCTModelBE(r.Birth, 8)))...)
	}
	if r.MasterPresent {
		out = append(out, syntheticCTModelAttr(0x800e, syntheticCTModelTuple(r.Master))...)
	}
	return out
}

func syntheticCTModelDrop(body []byte, drop uint16) []byte {
	out := append([]byte(nil), body[:4]...)
	for pos := 4; pos < len(body); {
		n := (int(binary.NativeEndian.Uint16(body[pos:])) + 3) &^ 3
		if binary.NativeEndian.Uint16(body[pos+2:])&0x3fff != drop {
			out = append(out, body[pos:pos+n]...)
		}
		pos += n
	}
	return out
}
func syntheticCTModelFrame(kind, flags uint16, body []byte) []byte {
	b := make([]byte, (16+len(body)+3)&^3)
	binary.NativeEndian.PutUint32(b, uint32(16+len(body)))
	binary.NativeEndian.PutUint16(b[4:], kind)
	binary.NativeEndian.PutUint16(b[6:], flags)
	binary.NativeEndian.PutUint32(b[8:], 17)
	binary.NativeEndian.PutUint32(b[12:], 29)
	copy(b[16:], body)
	return b
}
func syntheticCTModelMapping() dnscontrol.SyntheticDNSMappingObservation {
	return dnscontrol.SyntheticDNSMappingObservation{Client: netip.MustParseAddr("192.168.1.42"), Synthetic: netip.MustParseAddr("198.18.0.1"), RealIPv4: netip.MustParseAddr("93.184.215.14"), PossiblyIssued: true, LastPossiblyIssuedAt: time.Unix(100, 0), LastPossiblyIssuedTTLBound: 60}
}
func syntheticCTModelRow() syntheticCTRow {
	m := syntheticCTModelMapping()
	return syntheticCTRow{Original: syntheticCTTuple{Source: m.Client, Destination: m.Synthetic, SourcePort: 52000, DestinationPort: 443, Protocol: 6}, Reply: syntheticCTTuple{Source: m.RealIPv4, Destination: m.Client, SourcePort: 443, DestinationPort: 52000, Protocol: 6}, ID: 11, Status: 8 | 0x20 | 0x100, MarkPresent: true}
}
func syntheticCTModelImage(t *testing.T, frames ...[]byte) syntheticCTImage {
	t.Helper()
	d, err := newSyntheticCTDecoder(17, 29)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range frames {
		if err := d.consume(backendNFTDatagram{Data: f}); err != nil {
			t.Fatal(err)
		}
	}
	if err := d.consume(backendNFTDatagram{Data: syntheticCTModelFrame(3, 2, make([]byte, 4))}); err != nil {
		t.Fatal(err)
	}
	i, err := d.finishReceive(func() (backendNFTDatagram, bool, error) { return backendNFTDatagram{}, false, nil })
	if err != nil {
		t.Fatal(err)
	}
	return i
}

func TestSyntheticConntrackOldAndCurrentMultipartWireObservations(t *testing.T) {
	r := syntheticCTModelRow()
	r.Birth, r.BirthPresent = 123456789, true
	body := syntheticCTModelBody(r, 300)
	// Old 2.6.36 uses ordinary BE scalars; current NLA_F_NET_BYTEORDER
	// and the old missing nested flag are accepted only in typed positions.
	for _, flags := range []uint16{0, 0x4000, 0x8000} {
		d := append([]byte(nil), body...)
		for pos := 4; pos < len(d); {
			n := int(binary.NativeEndian.Uint16(d[pos:]))
			kind := binary.NativeEndian.Uint16(d[pos+2:]) & 0x3fff
			if kind == 3 {
				binary.NativeEndian.PutUint16(d[pos+2:], kind|(flags&0x4000))
			}
			if flags == 0x8000 && (kind == 1 || kind == 2) {
				binary.NativeEndian.PutUint16(d[pos+2:], kind)
			}
			pos += (n + 3) &^ 3
		}
		i := syntheticCTModelImage(t, syntheticCTModelFrame(syntheticCTNew, 2, d))
		if len(i.rows) != 1 || i.rows[0] != r {
			t.Fatal(i.rows)
		}
	}
	request, err := syntheticCTRequest(17, 29)
	if err != nil || len(request) != 20 || binary.NativeEndian.Uint16(request[4:]) != 0x101 || binary.NativeEndian.Uint16(request[6:]) != 0x301 || !reflect.DeepEqual(request[16:], []byte{2, 0, 0, 0}) {
		t.Fatal(request, err)
	}
}

func TestSyntheticConntrackLossABIAndTerminalRefusals(t *testing.T) {
	valid := syntheticCTModelFrame(syntheticCTNew, 2, syntheticCTModelBody(syntheticCTModelRow(), 300))
	for _, kind := range []string{"sender", "groups", "truncated", "ctruncated", "seq", "port", "flags", "filtered", "interrupted", "short", "length", "family", "version", "unknown-attr", "duplicate-attr", "missing-id", "bad-nest", "bad-padding", "error", "overrun", "done-error", "done-without-status", "after-done"} {
		t.Run(kind, func(t *testing.T) {
			d, _ := newSyntheticCTDecoder(17, 29)
			p := backendNFTDatagram{Data: append([]byte(nil), valid...)}
			switch kind {
			case "sender":
				p.SenderPID = 1
			case "groups":
				p.Groups = 1
			case "truncated":
				p.Truncated = true
			case "ctruncated":
				p.ControlTruncated = true
			case "seq":
				binary.NativeEndian.PutUint32(p.Data[8:], 18)
			case "port":
				binary.NativeEndian.PutUint32(p.Data[12:], 30)
			case "flags":
				binary.NativeEndian.PutUint16(p.Data[6:], 0)
			case "filtered":
				binary.NativeEndian.PutUint16(p.Data[6:], 0x22)
			case "interrupted":
				binary.NativeEndian.PutUint16(p.Data[6:], 0x12)
			case "short":
				p.Data = p.Data[:15]
			case "length":
				binary.NativeEndian.PutUint32(p.Data, uint32(len(p.Data)+1))
			case "family":
				p.Data[16] = 10
			case "version":
				p.Data[17] = 1
			case "unknown-attr":
				p.Data = syntheticCTModelFrame(syntheticCTNew, 2, append(syntheticCTModelBody(syntheticCTModelRow(), 300), syntheticCTModelAttr(99, nil)...))
			case "duplicate-attr":
				p.Data = syntheticCTModelFrame(syntheticCTNew, 2, append(syntheticCTModelBody(syntheticCTModelRow(), 300), syntheticCTModelAttr(12, make([]byte, 4))...))
			case "missing-id":
				p.Data = syntheticCTModelFrame(syntheticCTNew, 2, syntheticCTModelDrop(syntheticCTModelBody(syntheticCTModelRow(), 300), 12))
			case "bad-nest":
				binary.NativeEndian.PutUint16(p.Data[22:], 0x4001)
			case "bad-padding":
				body := append(syntheticCTModelBody(syntheticCTModelRow(), 300), syntheticCTModelAttr(5, []byte{1})...)
				body[len(body)-1] = 1
				p.Data = syntheticCTModelFrame(syntheticCTNew, 2, body)
			case "error":
				p.Data = syntheticCTModelFrame(2, 2, make([]byte, 24))
			case "overrun":
				p.Data = syntheticCTModelFrame(4, 2, nil)
			case "done-error":
				p.Data = syntheticCTModelFrame(3, 2, []byte{1, 0, 0, 0})
			case "done-without-status":
				p.Data = syntheticCTModelFrame(3, 2, nil)
			case "after-done":
				p.Data = append(syntheticCTModelFrame(3, 2, make([]byte, 4)), valid...)
			}
			if d.consume(p) == nil {
				t.Fatal("invalid wire accepted")
			}
			if _, err := d.finishReceive(func() (backendNFTDatagram, bool, error) { return backendNFTDatagram{}, false, nil }); err == nil {
				t.Fatal("failed image became empty evidence")
			}
		})
	}
	for _, kind := range []string{"no-done", "duplicate-id", "queued-after-done", "budget"} {
		t.Run(kind, func(t *testing.T) {
			d, _ := newSyntheticCTDecoder(17, 29)
			if err := d.consume(backendNFTDatagram{Data: valid}); err != nil {
				t.Fatal(err)
			}
			if kind == "duplicate-id" {
				if d.consume(backendNFTDatagram{Data: valid}) == nil {
					t.Fatal("duplicate ID admitted")
				}
			}
			if kind == "budget" {
				d.bytes = syntheticCTMaxBytes
				if d.consume(backendNFTDatagram{Data: valid}) == nil {
					t.Fatal("overflow admitted")
				}
			}
			if kind == "queued-after-done" {
				if err := d.consume(backendNFTDatagram{Data: syntheticCTModelFrame(3, 2, make([]byte, 4))}); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := d.finishReceive(func() (backendNFTDatagram, bool, error) {
				return backendNFTDatagram{}, kind == "queued-after-done", nil
			}); err == nil {
				t.Fatal("incomplete image admitted")
			}
		})
	}
}

func TestSyntheticConntrackAllMappingReferencesRemainCandidates(t *testing.T) {
	base, m, capture := syntheticCTModelRow(), syntheticCTModelMapping(), netip.MustParseAddrPort("192.168.1.1:10443")
	for _, kind := range []string{"standby", "capture", "snat", "udp", "other-port", "other-client", "zone", "tuple-zone", "helper", "offload", "missing-mark", "no-dnat", "wrong-reply", "reply-only", "master-only"} {
		t.Run(kind, func(t *testing.T) {
			r := base
			want := "unsupported"
			switch kind {
			case "standby":
				want = "standby-shaped"
			case "capture":
				r.Reply.Source = capture.Addr()
				r.Reply.SourcePort = capture.Port()
				want = "capture-shaped"
			case "snat":
				r.Reply.Destination = netip.MustParseAddr("203.0.113.9")
				r.Reply.DestinationPort = 12345
				r.Status |= 0x10 | 0x80
				want = "standby-shaped"
			case "udp":
				r.Original.Protocol = 17
				r.Reply.Protocol = 17
			case "other-port":
				r.Original.DestinationPort = 8443
			case "other-client":
				r.Original.Source = netip.MustParseAddr("192.168.1.99")
			case "zone":
				r.Zone = 3
			case "tuple-zone":
				r.Reply.Zone = 3
			case "helper":
				r.Unsafe = true
			case "offload":
				r.Status |= 0x4000
			case "missing-mark":
				r.MarkPresent = false
			case "no-dnat":
				r.Status = 8
			case "wrong-reply":
				r.Reply.DestinationPort = 44444
			case "reply-only":
				r.Original.Destination = m.RealIPv4
				r.Reply.Source = m.Synthetic
			case "master-only":
				r.Master, r.MasterPresent, r.Unsafe = r.Original, true, true
				r.Original.Destination = m.RealIPv4
			}
			i := syntheticCTImage{rows: []syntheticCTRow{r}, complete: true}
			o, err := compareSyntheticSettlement(i, i, m, capture)
			if err != nil || len(o.second) != 1 || o.second[0].kind != want || o.comparison != "unchanged" || o.pending == "" {
				t.Fatal(o, err)
			}
		})
	}
}

func TestSyntheticConntrackChangesAgingAndEmptyNeverSettle(t *testing.T) {
	r, m, capture := syntheticCTModelRow(), syntheticCTModelMapping(), netip.MustParseAddrPort("192.168.1.1:10443")
	first := syntheticCTModelImage(t, syntheticCTModelFrame(syntheticCTNew, 2, syntheticCTModelBody(r, 300)))
	aged := syntheticCTModelImage(t, syntheticCTModelFrame(syntheticCTNew, 2, syntheticCTModelBody(r, 299)))
	if o, err := compareSyntheticSettlement(first, aged, m, capture); err != nil || o.comparison != "unchanged" || o.pending == "" {
		t.Fatal(o, err)
	}
	for _, change := range []string{"id", "tuple", "reply", "mark", "status", "birth", "insert", "remove"} {
		t.Run(change, func(t *testing.T) {
			v := r
			second := syntheticCTImage{complete: true}
			switch change {
			case "id":
				v.ID++
			case "tuple":
				v.Original.SourcePort++
			case "reply":
				v.Reply.SourcePort++
			case "mark":
				v.Mark = 0x28000000
			case "status":
				v.Status |= 2
			case "birth":
				v.Birth = 9000
				v.BirthPresent = true
			case "insert":
				v.ID++
				second.rows = append(second.rows, r)
			}
			if change != "remove" {
				second.rows = append(second.rows, v)
			}
			o, err := compareSyntheticSettlement(first, second, m, capture)
			if err != nil || o.comparison != "changed" || o.pending == "" {
				t.Fatal(o, err)
			}
		})
	}
	empty := syntheticCTModelImage(t)
	o, err := compareSyntheticSettlement(empty, empty, m, capture)
	if err != nil || o.comparison != "unchanged" || o.pending == "" || !o.cacheDeadline.Before(time.Now()) {
		t.Fatal("empty/expired observation granted settlement", o, err)
	}
	if _, err := compareSyntheticSettlement(syntheticCTImage{}, empty, m, capture); err == nil {
		t.Fatal("missing complete dump became empty")
	}
}
