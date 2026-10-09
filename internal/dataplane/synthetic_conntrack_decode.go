package dataplane

import (
	"encoding/binary"
	"errors"
	"net/netip"
)

var errSyntheticConntrack = errors.New("complete original IPv4 conntrack observation unavailable")

const (
	syntheticCTGet          = uint16(0x101)
	syntheticCTNew          = uint16(0x100)
	syntheticCTMaxBytes     = 4 << 20
	syntheticCTMaxRows      = 32768
	syntheticCTMaxDatagrams = 2048
)

type syntheticCTTuple struct {
	Source, Destination         netip.Addr
	SourcePort, DestinationPort uint16
	Protocol                    uint8
	Zone                        uint16
	Auxiliary                   [6]uint16 // ICMP and other supported L4 attributes
}

// Kernel ID is only an observation. Linux 2.6.36 emits a truncated pointer;
// even equal ID/tuple images cannot rule out delete/reinsert (ABA).
type syntheticCTRow struct {
	Original, Reply  syntheticCTTuple
	Master           syntheticCTTuple
	MasterPresent    bool
	ID, Status, Mark uint32
	MarkPresent      bool
	Zone             uint16
	Birth            uint64
	BirthPresent     bool
	Unsafe           bool // helper/master/sequence adjustment or policy extensions
}

type syntheticCTImage struct {
	rows     []syntheticCTRow
	complete bool
}

type syntheticCTDecoder struct {
	sequence, port   uint32
	bytes, datagrams int
	done, failed     bool
	rows             []syntheticCTRow
	ids              map[uint32]bool
}

func syntheticCTRequest(sequence, port uint32) ([]byte, error) {
	if sequence == 0 || port == 0 {
		return nil, syntheticCTFailure(syntheticCTRequestIdentity, nil)
	}
	b := make([]byte, 20)
	binary.NativeEndian.PutUint32(b, 20)
	binary.NativeEndian.PutUint16(b[4:], syntheticCTGet)
	binary.NativeEndian.PutUint16(b[6:], 0x301) // REQUEST | DUMP; never DELETE/CTRZERO
	binary.NativeEndian.PutUint32(b[8:], sequence)
	binary.NativeEndian.PutUint32(b[12:], port)
	b[16] = 2 // AF_INET, NFNETLINK_V0, res_id=0
	return b, nil
}

func newSyntheticCTDecoder(sequence, port uint32) (*syntheticCTDecoder, error) {
	if _, err := syntheticCTRequest(sequence, port); err != nil {
		return nil, err
	}
	return &syntheticCTDecoder{sequence: sequence, port: port, ids: map[uint32]bool{}}, nil
}

func (d *syntheticCTDecoder) consume(packet backendNFTDatagram) (err error) {
	defer func() {
		if err != nil && d != nil {
			d.failed = true
		}
	}()
	if d == nil || d.failed || d.done {
		return syntheticCTFailure(syntheticCTState, nil)
	}
	if packet.SenderPID != 0 || packet.Groups != 0 {
		return syntheticCTFailure(syntheticCTSender, nil)
	}
	if packet.Truncated || packet.ControlTruncated {
		return syntheticCTFailure(syntheticCTTruncated, nil)
	}
	if len(packet.Data) == 0 {
		return syntheticCTFailure(syntheticCTEmpty, nil)
	}
	d.bytes += len(packet.Data)
	d.datagrams++
	if d.bytes > syntheticCTMaxBytes || d.datagrams > syntheticCTMaxDatagrams {
		return syntheticCTFailure(syntheticCTBudget, nil)
	}
	b := packet.Data
	for len(b) != 0 {
		if d.done {
			return syntheticCTFailure(syntheticCTState, nil)
		}
		if len(b) < 16 {
			return syntheticCTFailure(syntheticCTMessageLength, nil)
		}
		n := int(binary.NativeEndian.Uint32(b))
		if n < 16 || n > len(b) || (n+3)&^3 > len(b) {
			return syntheticCTFailure(syntheticCTMessageLength, nil)
		}
		kind, flags := binary.NativeEndian.Uint16(b[4:]), binary.NativeEndian.Uint16(b[6:])
		if flags != 2 {
			return syntheticCTFailure(syntheticCTMessageFlags, nil) // interrupted/filtered/unknown flags refuse
		}
		if binary.NativeEndian.Uint32(b[8:]) != d.sequence {
			return syntheticCTFailure(syntheticCTSequence, nil)
		}
		if binary.NativeEndian.Uint32(b[12:]) != d.port {
			return syntheticCTFailure(syntheticCTPort, nil)
		}
		if !backendAllZero(b[n : (n+3)&^3]) {
			return syntheticCTFailure(syntheticCTPadding, nil)
		}
		body := b[16:n]
		switch kind {
		case 3: // DONE carries one successful native-endian int, old/current ABI
			if len(body) != 4 || binary.NativeEndian.Uint32(body) != 0 {
				return syntheticCTFailure(syntheticCTDone, nil)
			}
			d.done = true
		case syntheticCTNew:
			row, err := decodeSyntheticCTRow(body)
			if err != nil {
				return err
			}
			if d.ids[row.ID] {
				return syntheticCTFailure(syntheticCTDuplicateID, nil)
			}
			if len(d.rows) >= syntheticCTMaxRows {
				return syntheticCTFailure(syntheticCTRowBudget, nil)
			}
			d.ids[row.ID] = true
			d.rows = append(d.rows, row)
		default:
			return syntheticCTFailure(syntheticCTMessageKind, nil) // ERROR/OVERRUN/ACK are never empty evidence
		}
		b = b[(n+3)&^3:]
	}
	return nil
}

// Caller drains the same unicast fd once after DONE. Any queued terminal or
// unexpected frame refuses; no multipart prefix can become a complete image.
func (d *syntheticCTDecoder) finishReceive(receive func() (backendNFTDatagram, bool, error)) (syntheticCTImage, error) {
	if d == nil || d.failed || !d.done || receive == nil {
		return syntheticCTImage{}, syntheticCTFailure(syntheticCTFinish, nil)
	}
	if _, queued, err := receive(); queued || err != nil {
		d.failed = true
		return syntheticCTImage{}, syntheticCTFailure(syntheticCTDrain, err)
	}
	return syntheticCTImage{rows: append([]syntheticCTRow(nil), d.rows...), complete: true}, nil
}

type syntheticCTAttr struct {
	flags uint16
	data  []byte
}

func syntheticCTAttrs(b []byte) (map[uint16]syntheticCTAttr, error) {
	out := map[uint16]syntheticCTAttr{}
	for len(b) != 0 {
		if len(b) < 4 {
			return nil, syntheticCTFailure(syntheticCTAttribute, nil)
		}
		n, raw := int(binary.NativeEndian.Uint16(b)), binary.NativeEndian.Uint16(b[2:])
		kind, flags := raw&0x3fff, raw&0xc000
		if n < 4 || n > len(b) || (n+3)&^3 > len(b) || kind == 0 || !backendAllZero(b[n:(n+3)&^3]) {
			return nil, syntheticCTFailure(syntheticCTAttribute, nil)
		}
		if _, duplicate := out[kind]; duplicate {
			return nil, syntheticCTFailure(syntheticCTDuplicateAttr, nil)
		}
		out[kind] = syntheticCTAttr{flags: flags, data: b[4:n]}
		b = b[(n+3)&^3:]
	}
	return out, nil
}

func (a syntheticCTAttr) scalar(size int, network bool) bool {
	return len(a.data) == size && (a.flags == 0 || network && a.flags == 0x4000)
}
func (a syntheticCTAttr) nested() (map[uint16]syntheticCTAttr, error) {
	if a.flags != 0 && a.flags != 0x8000 {
		return nil, syntheticCTFailure(syntheticCTNestedFlags, nil)
	}
	return syntheticCTAttrs(a.data)
}

func decodeSyntheticCTRow(body []byte) (syntheticCTRow, error) {
	var r syntheticCTRow
	if len(body) < 4 || body[0] != 2 || !backendAllZero(body[1:4]) {
		return r, syntheticCTFailure(syntheticCTFamily, nil)
	}
	a, err := syntheticCTAttrs(body[4:])
	if err != nil {
		return r, err
	}
	if r.Original, err = decodeSyntheticCTTuple(a[1]); err != nil {
		return r, err
	}
	if r.Reply, err = decodeSyntheticCTTuple(a[2]); err != nil {
		return r, err
	}
	if r.Reply.Protocol != r.Original.Protocol {
		return r, syntheticCTFailure(syntheticCTReplyProtocol, nil)
	}
	if !a[3].scalar(4, true) {
		return r, syntheticCTFailure(syntheticCTStatusShape, nil)
	}
	if !a[12].scalar(4, true) {
		return r, syntheticCTFailure(syntheticCTIDShape, nil)
	}
	r.Status, r.ID = binary.BigEndian.Uint32(a[3].data), binary.BigEndian.Uint32(a[12].data)
	if r.ID == 0 {
		return r, syntheticCTFailure(syntheticCTZeroID, nil)
	}
	if r.Status&^uint32(0xffff) != 0 {
		return r, syntheticCTFailure(syntheticCTStatusMask, nil)
	}
	for kind, v := range a {
		switch kind {
		case 1, 2, 3, 12:
		case 7, 8, 11, 17:
			if !v.scalar(4, true) {
				return r, syntheticCTFailure(syntheticCTRowShape, nil)
			}
			if kind == 8 {
				r.Mark, r.MarkPresent = binary.BigEndian.Uint32(v.data), true
			}
			if kind == 17 {
				r.Unsafe = true
			}
		case 18:
			if !v.scalar(2, true) {
				return r, syntheticCTFailure(syntheticCTRowShape, nil)
			}
			r.Zone = binary.BigEndian.Uint16(v.data)
		case 9, 10:
			if err := syntheticCTFixedNest(v, map[uint16]int{1: 8, 2: 8, 3: 4, 4: 4, 5: 0}, true); err != nil {
				return r, err
			}
		case 4:
			p, err := v.nested()
			if err != nil || len(p) != 1 {
				return r, syntheticCTFailure(syntheticCTRowShape, nil)
			}
			for proto, info := range p {
				var sizes map[uint16]int
				switch proto {
				case 1:
					if r.Original.Protocol != 6 {
						return r, syntheticCTFailure(syntheticCTRowShape, nil)
					}
					sizes = map[uint16]int{1: 1, 2: 1, 3: 1, 4: 2, 5: 2}
				case 2:
					if r.Original.Protocol != 33 {
						return r, syntheticCTFailure(syntheticCTRowShape, nil)
					}
					sizes = map[uint16]int{1: 1, 2: 1, 3: 8, 4: 0}
				case 3:
					if r.Original.Protocol != 132 {
						return r, syntheticCTFailure(syntheticCTRowShape, nil)
					}
					sizes = map[uint16]int{1: 1, 2: 4, 3: 4}
				default:
					return r, syntheticCTFailure(syntheticCTRowShape, nil)
				}
				if err := syntheticCTFixedNest(info, sizes, true); err != nil {
					return r, err
				}
			}
		case 20:
			stamp, err := v.nested()
			if err != nil {
				return r, err
			}
			for k, val := range stamp {
				if k == 3 && val.scalar(0, false) {
					continue
				}
				if (k != 1 && k != 2) || !val.scalar(8, true) {
					return r, syntheticCTFailure(syntheticCTRowShape, nil)
				}
				if k == 1 {
					r.Birth, r.BirthPresent = binary.BigEndian.Uint64(val.data), true
				}
			}
		case 14:
			if r.Master, err = decodeSyntheticCTTuple(v); err != nil {
				return r, err
			}
			r.MasterPresent = true
			r.Unsafe = true
		case 15, 16:
			if err := syntheticCTFixedNest(v, map[uint16]int{1: 4, 2: 4, 3: 4}, true); err != nil {
				return r, err
			}
			r.Unsafe = true
		case 5:
			h, err := v.nested()
			if err != nil || len(h) != 1 {
				return r, syntheticCTFailure(syntheticCTRowShape, nil)
			}
			name := h[1]
			if name.flags != 0 || len(name.data) < 2 || len(name.data) > 64 || name.data[len(name.data)-1] != 0 {
				return r, syntheticCTFailure(syntheticCTRowShape, nil)
			}
			r.Unsafe = true
		case 24:
			return r, syntheticCTFailure(syntheticCTAttr24, nil)
		case 25:
			return r, syntheticCTFailure(syntheticCTAttr25, nil)
		case 26:
			return r, syntheticCTFailure(syntheticCTAttr26, nil)
		default:
			// The supported subset is explicit. An extension, absent ID or
			// malformed foreign row makes FULL coverage unknown, never zero.
			return r, syntheticCTFailure(syntheticCTUnknownAttr, nil)
		}
	}
	return r, nil
}

func syntheticCTFixedNest(v syntheticCTAttr, sizes map[uint16]int, network bool) error {
	a, err := v.nested()
	if err != nil {
		return err
	}
	for k, value := range a {
		size, known := sizes[k]
		if !known || !value.scalar(size, network) {
			return syntheticCTFailure(syntheticCTRowShape, nil)
		}
	}
	return nil
}

func decodeSyntheticCTTuple(v syntheticCTAttr) (syntheticCTTuple, error) {
	var tuple syntheticCTTuple
	a, err := v.nested()
	if err != nil || len(a) < 2 || len(a) > 3 {
		return tuple, syntheticCTFailure(syntheticCTTupleShape, err)
	}
	for k := range a {
		if k != 1 && k != 2 && k != 3 {
			return tuple, syntheticCTFailure(syntheticCTTupleShape, err)
		}
	}
	ip, err := a[1].nested()
	if err != nil || len(ip) != 2 || !ip[1].scalar(4, true) || !ip[2].scalar(4, true) {
		return tuple, syntheticCTFailure(syntheticCTTupleShape, err)
	}
	tuple.Source = netip.AddrFrom4([4]byte(ip[1].data))
	tuple.Destination = netip.AddrFrom4([4]byte(ip[2].data))
	proto, err := a[2].nested()
	if err != nil || !proto[1].scalar(1, false) {
		return tuple, syntheticCTFailure(syntheticCTTupleShape, err)
	}
	tuple.Protocol = proto[1].data[0]
	for k, value := range proto {
		size := 1
		switch k {
		case 1, 5, 6, 8, 9:
		case 2, 3, 4, 7:
			size = 2
		default:
			return tuple, syntheticCTFailure(syntheticCTTupleShape, err)
		}
		if !value.scalar(size, size == 2) {
			return tuple, syntheticCTFailure(syntheticCTTupleShape, err)
		}
		if k == 2 {
			tuple.SourcePort = binary.BigEndian.Uint16(value.data)
		}
		if k == 3 {
			tuple.DestinationPort = binary.BigEndian.Uint16(value.data)
		}
		if k >= 4 {
			if size == 1 {
				tuple.Auxiliary[k-4] = uint16(value.data[0])
			} else {
				tuple.Auxiliary[k-4] = binary.BigEndian.Uint16(value.data)
			}
		}
	}
	if tuple.Protocol == 6 || tuple.Protocol == 17 {
		if len(proto) != 3 || !proto[2].scalar(2, true) || !proto[3].scalar(2, true) {
			return tuple, syntheticCTFailure(syntheticCTTupleShape, err)
		}
	}
	if zone, ok := a[3]; ok {
		if !zone.scalar(2, true) {
			return tuple, syntheticCTFailure(syntheticCTTupleShape, err)
		}
		tuple.Zone = binary.BigEndian.Uint16(zone.data)
	}
	return tuple, nil
}
