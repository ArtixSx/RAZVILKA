package dataplane

import (
	"encoding/binary"
	"errors"
	"testing"
)

func backendNFTModernGenFixture() []byte {
	body := append([]byte(nil), backendNFTTestGen()[16:]...)
	body = append(body, backendNFTTestAttr(2, backendNFTTestU32(4242))...)
	body = append(body, backendNFTTestAttr(3, []byte("qa\x00"))...)
	return backendNFTTestFrame(backendNFTNewGen, 0, body)
}
func backendNFTModernTableFixture(family uint8, flags uint32) []byte {
	body := []byte{family, 0, 0, 23}
	body = append(body, backendNFTTestAttr(1, []byte("modern\x00"))...)
	body = append(body, backendNFTTestAttr(3, backendNFTTestU32(2))...)
	body = append(body, backendNFTTestAttr(5, nil)...)
	handle := make([]byte, 8)
	binary.BigEndian.PutUint64(handle, 99)
	body = append(body, backendNFTTestAttr(4, handle)...)
	body = append(body, backendNFTTestAttr(2, backendNFTTestU32(flags))...)
	if flags&2 != 0 {
		body = append(body, backendNFTTestAttr(7, backendNFTTestU32(333))...)
	}
	body = append(body, backendNFTTestAttr(6, []byte{1, 2, 3})...)
	return backendNFTTestFrame(backendNFTNewTable, 2, body)
}
func backendNFTABIDecoderFixture(t *testing.T, kind uint16, abi backendNFTABI, budget *backendNFTBudget) *backendNFTDecoder {
	t.Helper()
	request, err := backendNFTRequest(kind, 19, 2345)
	if err != nil {
		t.Fatal("request failed")
	}
	if budget == nil {
		budget = &backendNFTBudget{}
	}
	d, err := newBackendNFTDecoderABI(request, 23, budget, abi)
	if err != nil {
		t.Fatal("decoder failed")
	}
	return d
}
func backendNFTEmptyQueueFixture() (backendNFTDatagram, bool, error) {
	return backendNFTDatagram{}, false, nil
}

func TestBackendNFTLinux70KnownGENACKAndTableShapes(t *testing.T) {
	d := backendNFTABIDecoderFixture(t, backendNFTGetGen, backendNFTABILinux70, nil)
	ack := backendNFTTestACK(d.request, 0)
	binary.NativeEndian.PutUint16(ack[6:], 0x100)
	if d.consume(backendNFTTestPacket(backendNFTModernGenFixture())) != nil || d.consume(backendNFTTestPacket(ack)) != nil || d.closeReceive(backendNFTEmptyQueueFixture) != nil {
		t.Fatal("modern GEN + CAPPED ACK failed")
	}
	observation, err := d.registration()
	if err != nil || !observation.valid(backendNFTABILinux70) || observation.generation != 23 || observation.noRegistered {
		t.Fatal("modern generation became absence")
	}
	for _, family := range []uint8{1, 2, 3, 5, 7, 10} {
		for _, flags := range []uint32{0, 1, 2, 3, 4, 5, 6, 7} {
			d := backendNFTABIDecoderFixture(t, backendNFTGetTable, backendNFTABILinux70, nil)
			if d.consume(backendNFTTestPacket(append(backendNFTModernTableFixture(family, flags), backendNFTTestDone()...))) != nil || d.closeReceive(backendNFTEmptyQueueFixture) != nil || len(d.tables) != 1 || d.tables[0].Family != family || d.tables[0].Flags != flags {
				t.Fatal("known modern table metadata lost")
			}
		}
	}
}

func TestBackendNFTLinux70UnknownExtensionsAndWrongABIRefuse(t *testing.T) {
	for _, which := range []string{"old-gen", "old-ack", "unknown-gen-attr", "gen-name-BE", "unknown-table-attr", "wrong-handle", "unknown-table-flags", "owner-without-flag", "userdata-overflow", "foreign-family", "interrupted-dump", "extra-queued"} {
		t.Run(which, func(t *testing.T) {
			kind := uint16(backendNFTGetGen)
			if which == "unknown-table-attr" || which == "wrong-handle" || which == "unknown-table-flags" || which == "owner-without-flag" || which == "userdata-overflow" || which == "foreign-family" || which == "interrupted-dump" {
				kind = backendNFTGetTable
			}
			d := backendNFTABIDecoderFixture(t, kind, backendNFTABILinux70, nil)
			gen := backendNFTModernGenFixture()
			ack := backendNFTTestACK(d.request, 0)
			binary.NativeEndian.PutUint16(ack[6:], 0x100)
			table := backendNFTModernTableFixture(2, 0)
			switch which {
			case "old-gen":
				gen = backendNFTTestGen()
			case "old-ack":
				binary.NativeEndian.PutUint16(ack[6:], 0)
			case "unknown-gen-attr":
				gen = backendNFTTestFrame(backendNFTNewGen, 0, append(gen[16:], backendNFTTestAttr(4, backendNFTTestU32(1))...))
			case "gen-name-BE":
				binary.NativeEndian.PutUint16(gen[38:], 0x4003)
			case "unknown-table-attr":
				table = backendNFTTestFrame(backendNFTNewTable, 2, append(table[16:], backendNFTTestAttr(8, nil)...))
			case "wrong-handle":
				body := append([]byte(nil), table[16:44]...)
				body = append(body, backendNFTTestAttr(4, backendNFTTestU32(99))...)
				table = backendNFTTestFrame(backendNFTNewTable, 2, append(body, table[56:]...))
			case "unknown-table-flags":
				table = backendNFTModernTableFixture(2, 8)
			case "owner-without-flag":
				table = backendNFTTestFrame(backendNFTNewTable, 2, append(table[16:], backendNFTTestAttr(7, backendNFTTestU32(1))...))
			case "userdata-overflow":
				table = backendNFTTestFrame(backendNFTNewTable, 2, append(table[16:len(table)-8], backendNFTTestAttr(6, make([]byte, 257))...))
			case "foreign-family":
				table[16] = 99
			case "interrupted-dump":
				binary.NativeEndian.PutUint16(table[6:], 0x12)
			}
			data := append(gen, ack...)
			if kind == backendNFTGetTable {
				data = append(table, backendNFTTestDone()...)
			}
			err := d.consume(backendNFTTestPacket(data))
			if err == nil {
				if which == "extra-queued" {
					err = d.closeReceive(func() (backendNFTDatagram, bool, error) { return backendNFTTestPacket(gen), true, nil })
				} else {
					err = d.closeReceive(backendNFTEmptyQueueFixture)
				}
			}
			if !errors.Is(err, errBackendInventory) || d.finish() == nil {
				t.Fatal("unknown ABI response completed")
			}
		})
	}
}

func TestBackendNFTStockSoleNegativeProofNeedsTerminalEmptyQueue(t *testing.T) {
	d := backendNFTABIDecoderFixture(t, backendNFTGetGen, backendNFTABIStockNC1812, nil)
	if d.consume(backendNFTTestPacket(backendNFTTestACK(d.request, -22))) != nil || !d.negative || d.finish() == nil {
		t.Fatal("negative candidate was not kept incomplete before drain")
	}
	if _, err := d.registration(); !errors.Is(err, errBackendInventory) {
		t.Fatal("candidate became absence without drain")
	}
	if d.closeReceive(backendNFTEmptyQueueFixture) != nil {
		t.Fatal("sole negative did not close")
	}
	got, err := d.registration()
	if err != nil || !got.valid(backendNFTABIStockNC1812) || got.valid(backendNFTABILinux70) || !got.noRegistered || got.generation != 0 {
		t.Fatal("exact sole negative classification failed")
	}
}

func TestBackendNFTStockSoleNegativeRejectsAmbiguousResponse(t *testing.T) {
	for _, which := range []string{"generic49", "generic70", "gettable", "not-first-request", "gen-before", "ack-before", "gen-after", "ack-after", "junk-after", "second-datagram", "queued-gen", "queued-error", "drain-error", "wrong-echo", "wrong-seq", "wrong-port", "sender", "multicast", "trunc", "ctrunc", "capped-error", "other-errno", "wrong-nfgen"} {
		t.Run(which, func(t *testing.T) {
			abi := backendNFTABIStockNC1812
			kind := uint16(backendNFTGetGen)
			budget := &backendNFTBudget{}
			if which == "generic49" {
				abi = backendNFTABI49
			}
			if which == "generic70" {
				abi = backendNFTABILinux70
			}
			if which == "gettable" {
				kind = backendNFTGetTable
			}
			if which == "not-first-request" {
				budget.requests = 1
			}
			d := backendNFTABIDecoderFixture(t, kind, abi, budget)
			data := backendNFTTestACK(d.request, -22)
			switch which {
			case "gen-before":
				data = append(backendNFTTestGen(), data...)
			case "ack-before":
				data = append(backendNFTTestACK(d.request, 0), data...)
			case "gen-after":
				data = append(data, backendNFTTestGen()...)
			case "ack-after":
				data = append(data, backendNFTTestACK(d.request, 0)...)
			case "junk-after":
				data = append(data, 0)
			case "wrong-echo":
				data[28] ^= 1
			case "wrong-seq":
				data[8] ^= 1
			case "wrong-port":
				data[12] ^= 1
			case "capped-error":
				binary.NativeEndian.PutUint16(data[6:], 0x100)
			case "other-errno":
				data = backendNFTTestACK(d.request, -1)
			case "wrong-nfgen":
				data[39] = 1
			}
			packet := backendNFTTestPacket(data)
			switch which {
			case "sender":
				packet.SenderPID = 1
			case "multicast":
				packet.Groups = 1
			case "trunc":
				packet.Truncated = true
			case "ctrunc":
				packet.ControlTruncated = true
			}
			err := d.consume(packet)
			if err == nil {
				if which == "second-datagram" {
					err = d.consume(backendNFTTestPacket(backendNFTTestGen()))
				} else {
					err = d.closeReceive(func() (backendNFTDatagram, bool, error) {
						switch which {
						case "queued-gen":
							return backendNFTTestPacket(backendNFTTestGen()), true, nil
						case "queued-error":
							return backendNFTTestPacket(backendNFTTestACK(d.request, -22)), true, nil
						case "drain-error":
							return backendNFTDatagram{}, false, errors.New("transport unknown")
						}
						return backendNFTEmptyQueueFixture()
					})
				}
			}
			if !errors.Is(err, errBackendInventory) || d.finish() == nil {
				t.Fatal("ambiguous negative exchange completed")
			}
			if got, err := d.registration(); err == nil || got.noRegistered || got.sealed {
				t.Fatal("refused response leaked absence proof")
			}
		})
	}
}
