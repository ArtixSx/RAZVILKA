package dataplane

import (
	"bytes"
	"encoding/binary"
	"strings"
	"unicode/utf8"
)

const (
	backendNFTMaxBytes     = 256 << 10
	backendNFTMaxDatagrams = 64
	backendNFTMaxFrames    = 1024
	backendNFTMaxDatagram  = 64 << 10
	backendNFTGetTable     = 0x0a01
	backendNFTNewTable     = 0x0a00
	backendNFTGetGen       = 0x0a10
	backendNFTNewGen       = 0x0a0f
)

type backendNFTBudget struct{ bytes, datagrams, frames, requests int }
type backendNFTDatagram struct {
	Data                        []byte
	SenderPID, Groups           uint32
	Truncated, ControlTruncated bool
}

// Native-endian netlink header, network-endian nfgen res_id and integer NLA.
// Fixed UNSPEC GETs only; no batch, table name, mutation, group or setns input.
func backendNFTRequest(kind uint16, sequence, port uint32) ([]byte, error) {
	if sequence == 0 || port == 0 || kind != backendNFTGetGen && kind != backendNFTGetTable {
		return nil, errBackendInventory
	}
	data := make([]byte, 20)
	binary.NativeEndian.PutUint32(data, 20)
	binary.NativeEndian.PutUint16(data[4:], kind)
	flags := uint16(5) // REQUEST | ACK
	if kind == backendNFTGetTable {
		flags |= 0x300
	} // ROOT | MATCH (DUMP)
	binary.NativeEndian.PutUint16(data[6:], flags)
	binary.NativeEndian.PutUint32(data[8:], sequence)
	binary.NativeEndian.PutUint32(data[12:], port)
	return data, nil
}

type backendNFTDecoder struct {
	request                    []byte
	budget                     *backendNFTBudget
	kind                       uint16
	sequence, port, generation uint32
	genSeen, ackSeen, done     bool
	failed                     bool
	tables                     []backendNFTTable
	names                      map[string]bool
}

func newBackendNFTDecoder(request []byte, expectedGeneration uint32, budget *backendNFTBudget) (*backendNFTDecoder, error) {
	if len(request) != 20 || budget == nil || budget.requests >= 3 {
		return nil, errBackendInventory
	}
	kind := binary.NativeEndian.Uint16(request[4:])
	seq, port := binary.NativeEndian.Uint32(request[8:]), binary.NativeEndian.Uint32(request[12:])
	canonical, err := backendNFTRequest(kind, seq, port)
	if err != nil || !bytes.Equal(request, canonical) {
		return nil, errBackendInventory
	}
	budget.requests++
	return &backendNFTDecoder{request: append([]byte(nil), request...), budget: budget, kind: kind, sequence: seq, port: port, generation: expectedGeneration, names: map[string]bool{}}, nil
}

func (d *backendNFTDecoder) consume(packet backendNFTDatagram) (err error) {
	if d != nil {
		defer func() {
			if err != nil {
				d.failed = true
				d.done = false
				d.tables = nil
			}
		}()
	}
	if d == nil || d.failed || d.done || packet.SenderPID != 0 || packet.Groups != 0 || packet.Truncated || packet.ControlTruncated || len(packet.Data) == 0 || len(packet.Data) > backendNFTMaxDatagram || len(packet.Data) > backendNFTMaxBytes-d.budget.bytes || d.budget.datagrams >= backendNFTMaxDatagrams {
		return errBackendInventory
	}
	d.budget.bytes += len(packet.Data)
	d.budget.datagrams++
	for data := packet.Data; len(data) != 0; {
		if d.done || len(data) < 16 || d.budget.frames >= backendNFTMaxFrames {
			return errBackendInventory
		}
		d.budget.frames++
		n := int(binary.NativeEndian.Uint32(data))
		if n < 16 || n > len(data) {
			return errBackendInventory
		}
		aligned := (n + 3) &^ 3
		if aligned > len(data) || !backendAllZero(data[n:aligned]) {
			return errBackendInventory
		}
		kind, flags := binary.NativeEndian.Uint16(data[4:]), binary.NativeEndian.Uint16(data[6:])
		// Sender sockaddr is kernel PID 0. Header PID is this destination
		// socket's assigned port, including Linux 4.9 ACK/DONE messages.
		if binary.NativeEndian.Uint32(data[8:]) != d.sequence || binary.NativeEndian.Uint32(data[12:]) != d.port {
			return errBackendInventory
		}
		body := data[16:n]
		switch kind {
		case 2: // NLMSG_ERROR; CAP_ACK and EXT_ACK were not enabled.
			if flags != 0 || len(body) < 20 || !bytes.Equal(body[4:20], d.request[:16]) {
				return errBackendInventory
			}
			code := int32(binary.NativeEndian.Uint32(body))
			if code < 0 {
				if code < -4095 {
					return errBackendInventory
				}
				if len(body) != 24 || !bytes.Equal(body[4:], d.request) {
					return errBackendInventory
				}
				return &backendNFTKernelError{Code: -code}
			}
			if code != 0 || len(body) != 20 || d.kind != backendNFTGetGen || d.ackSeen {
				return errBackendInventory
			}
			d.ackSeen = true
			d.done = d.genSeen
		case 3: // NLMSG_DONE. A successful 4.9 dump has no extra ACK.
			if d.kind != backendNFTGetTable || flags != 2 || len(body) != 4 || binary.NativeEndian.Uint32(body) != 0 {
				return errBackendInventory
			}
			d.done = true
		case backendNFTNewGen:
			if d.kind != backendNFTGetGen || flags != 0 || d.genSeen || len(body) < 4 || body[0] != 0 || body[1] != 0 {
				return errBackendInventory
			}
			attrs, err := backendNFTAttrs(body[4:], 1)
			if err != nil || len(attrs) != 1 || len(attrs[1]) != 4 {
				return errBackendInventory
			}
			d.generation = binary.BigEndian.Uint32(attrs[1])
			if binary.BigEndian.Uint16(body[2:]) != uint16(d.generation) {
				return errBackendInventory
			}
			d.genSeen = true
			d.done = d.ackSeen
		case backendNFTNewTable:
			if d.kind != backendNFTGetTable || flags != 2 || len(body) < 4 || body[1] != 0 || !backendNFTFamily(body[0]) || binary.BigEndian.Uint16(body[2:]) != uint16(d.generation) {
				return errBackendInventory
			}
			attrs, err := backendNFTAttrs(body[4:], 3)
			if err != nil || len(attrs) != 3 || len(attrs[1]) < 2 || len(attrs[1]) > 32 || attrs[1][len(attrs[1])-1] != 0 || bytes.IndexByte(attrs[1][:len(attrs[1])-1], 0) >= 0 || len(attrs[2]) != 4 || len(attrs[3]) != 4 {
				return errBackendInventory
			}
			name := string(attrs[1][:len(attrs[1])-1])
			if !utf8.ValidString(name) || strings.IndexFunc(name, func(c rune) bool { return c < 32 || c == 127 }) >= 0 {
				return errBackendInventory
			}
			key := string([]byte{body[0]}) + name
			flags := binary.BigEndian.Uint32(attrs[2])
			if d.names[key] || flags&^1 != 0 {
				return errBackendInventory
			}
			d.names[key] = true
			d.tables = append(d.tables, backendNFTTable{Family: body[0], Name: name, Flags: flags, Use: binary.BigEndian.Uint32(attrs[3])})
		default: // NOOP, OVERRUN, events and unknown extensions refuse.
			return errBackendInventory
		}
		data = data[aligned:]
	}
	return nil
}

func (d *backendNFTDecoder) finish() error {
	if d == nil || d.failed || !d.done {
		return errBackendInventory
	}
	return nil
}

// Closed Linux 4.9 read ABI. Unknown attributes (including a newer table
// handle/owner) are Unknown, never silently accepted as an empty namespace.
// Known BE integer attributes may carry NLA_F_NET_BYTEORDER; nesting refuses.
func backendNFTAttrs(data []byte, max uint16) (map[uint16][]byte, error) {
	attrs := make(map[uint16][]byte, max)
	for len(data) != 0 {
		if len(data) < 4 {
			return nil, errBackendInventory
		}
		n, raw := int(binary.NativeEndian.Uint16(data)), binary.NativeEndian.Uint16(data[2:])
		kind, flags := raw&0x3fff, raw&0xc000
		aligned := (n + 3) &^ 3
		if n < 4 || aligned > len(data) || kind == 0 || kind > max || attrs[kind] != nil || !backendAllZero(data[n:aligned]) || flags != 0 && (flags != 0x4000 || max == 3 && kind == 1) {
			return nil, errBackendInventory
		}
		attrs[kind] = data[4:n]
		data = data[aligned:]
	}
	return attrs, nil
}

func backendAllZero(data []byte) bool {
	for _, value := range data {
		if value != 0 {
			return false
		}
	}
	return true
}

func backendNFTFamily(family uint8) bool {
	switch family {
	case 1, 2, 3, 5, 7, 10:
		return true
	} // inet/ip/arp/netdev/bridge/ip6
	return false
}
