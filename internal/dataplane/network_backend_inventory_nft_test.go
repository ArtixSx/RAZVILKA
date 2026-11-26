package dataplane

import (
	"encoding/binary"
	"errors"
	"fmt"
	"testing"
)

// Wire fixtures follow the pinned v4.9 nf_tables_fill_* and netlink_ack ABI,
// including destination port in response headers and no successful dump ACK.
func backendNFTTestAttr(kind uint16, body []byte) []byte {
	n := 4 + len(body)
	data := make([]byte, (n+3)&^3)
	binary.NativeEndian.PutUint16(data, uint16(n))
	binary.NativeEndian.PutUint16(data[2:], kind)
	copy(data[4:], body)
	return data
}
func backendNFTTestU32(value uint32) []byte {
	data := make([]byte, 4)
	binary.BigEndian.PutUint32(data, value)
	return data
}
func backendNFTTestFrame(kind, flags uint16, body []byte) []byte {
	n := 16 + len(body)
	data := make([]byte, (n+3)&^3)
	binary.NativeEndian.PutUint32(data, uint32(n))
	binary.NativeEndian.PutUint16(data[4:], kind)
	binary.NativeEndian.PutUint16(data[6:], flags)
	binary.NativeEndian.PutUint32(data[8:], 19)
	binary.NativeEndian.PutUint32(data[12:], 2345)
	copy(data[16:], body)
	return data
}
func backendNFTTestGen() []byte {
	body := []byte{0, 0, 0, 23}
	body = append(body, backendNFTTestAttr(1, backendNFTTestU32(23))...)
	return backendNFTTestFrame(backendNFTNewGen, 0, body)
}
func backendNFTTestTable(family uint8) []byte {
	body := []byte{family, 0, 0, 23}
	body = append(body, backendNFTTestAttr(1, []byte("foreign\x00"))...)
	body = append(body, backendNFTTestAttr(2, backendNFTTestU32(1))...)
	body = append(body, backendNFTTestAttr(3, backendNFTTestU32(4))...)
	return backendNFTTestFrame(backendNFTNewTable, 2, body)
}
func backendNFTTestACK(request []byte, code int32) []byte {
	body := make([]byte, 4)
	binary.NativeEndian.PutUint32(body, uint32(code))
	if code == 0 {
		body = append(body, request[:16]...)
	} else {
		body = append(body, request...)
	}
	return backendNFTTestFrame(2, 0, body)
}
func backendNFTTestDone() []byte { return backendNFTTestFrame(3, 2, make([]byte, 4)) }
func backendNFTTestDecoder(t *testing.T, kind uint16, budget *backendNFTBudget) *backendNFTDecoder {
	t.Helper()
	req, err := backendNFTRequest(kind, 19, 2345)
	if err != nil {
		t.Fatal(err)
	}
	if budget == nil {
		budget = &backendNFTBudget{}
	}
	d, err := newBackendNFTDecoder(req, 23, budget)
	if err != nil {
		t.Fatal(err)
	}
	return d
}
func backendNFTTestPacket(data []byte) backendNFTDatagram { return backendNFTDatagram{Data: data} }

func TestBackendNFTGenRequiresExactACK(t *testing.T) {
	d := backendNFTTestDecoder(t, backendNFTGetGen, nil)
	if err := d.consume(backendNFTTestPacket(backendNFTTestGen())); err != nil {
		t.Fatal(err)
	}
	if d.finish() == nil {
		t.Fatal("generation without ACK accepted")
	}
	if err := d.consume(backendNFTTestPacket(backendNFTTestACK(d.request, 0))); err != nil {
		t.Fatal(err)
	}
	if err := d.finish(); err != nil || d.generation != 23 {
		t.Fatalf("gen failed %v", err)
	}
	if err := d.consume(backendNFTTestPacket(backendNFTTestACK(d.request, 0))); err == nil {
		t.Fatal("duplicate terminal ACK accepted")
	}
	for _, kind := range []uint16{backendNFTGetGen, backendNFTGetTable} {
		req, err := backendNFTRequest(kind, 19, 2345)
		if err != nil || len(req) != 20 || !backendAllZero(req[16:]) {
			t.Fatalf("not a fixed UNSPEC GET: %x %v", req, err)
		}
		want := uint16(5)
		if kind == backendNFTGetTable {
			want |= 0x300
		}
		if binary.NativeEndian.Uint16(req[6:]) != want {
			t.Fatal("request flags changed")
		}
	}
}

func TestBackendNFTDumpEmptyAndForeignFamilies(t *testing.T) {
	d := backendNFTTestDecoder(t, backendNFTGetTable, nil)
	if err := d.consume(backendNFTTestPacket(backendNFTTestDone())); err != nil || d.finish() != nil || len(d.tables) != 0 {
		t.Fatalf("empty terminal dump failed: %v", err)
	}
	for _, family := range []uint8{1, 2, 3, 5, 7, 10} {
		t.Run(fmt.Sprint(family), func(t *testing.T) {
			d := backendNFTTestDecoder(t, backendNFTGetTable, nil)
			if err := d.consume(backendNFTTestPacket(append(backendNFTTestTable(family), backendNFTTestDone()...))); err != nil {
				t.Fatal(err)
			}
			if d.finish() != nil || len(d.tables) != 1 || d.tables[0].Family != family || d.tables[0].Flags != 1 || d.tables[0].Use != 4 {
				t.Fatalf("foreign family lost: %+v", d.tables)
			}
		})
	}
}

func TestBackendNFTEINVALIsSealedDiagnosticOnly(t *testing.T) {
	for _, kind := range []uint16{backendNFTGetGen, backendNFTGetTable} {
		d := backendNFTTestDecoder(t, kind, nil)
		err := d.consume(backendNFTTestPacket(backendNFTTestACK(d.request, -22)))
		var refusal *backendNFTKernelError
		if !errors.As(err, &refusal) || refusal.Code != 22 || !errors.Is(err, errBackendInventory) || d.finish() == nil {
			t.Fatalf("EINVAL became absence: %v", err)
		}
		for _, offset := range []int{20, 24, 28, 32, 36} {
			d := backendNFTTestDecoder(t, kind, nil)
			data := backendNFTTestACK(d.request, -22)
			data[offset] ^= 1
			err := d.consume(backendNFTTestPacket(data))
			refusal = nil
			if err == nil || errors.As(err, &refusal) {
				t.Fatalf("unsealed error echo offset %d accepted: %v", offset, err)
			}
		}
	}
}

func TestBackendNFTRejectsTruncatedEveryPrefix(t *testing.T) {
	for _, kind := range []uint16{backendNFTGetGen, backendNFTGetTable} {
		d := backendNFTTestDecoder(t, kind, nil)
		full := append(backendNFTTestGen(), backendNFTTestACK(d.request, 0)...)
		if kind == backendNFTGetTable {
			full = append(backendNFTTestTable(7), backendNFTTestDone()...)
		}
		for cut := 0; cut < len(full); cut++ {
			d := backendNFTTestDecoder(t, kind, nil)
			err := d.consume(backendNFTTestPacket(full[:cut]))
			if err == nil && d.finish() == nil {
				t.Fatalf("truncated %x cut=%d granted complete read", kind, cut)
			}
		}
	}
}

func TestBackendNFTRejectsMalformedAndUntrustedFrames(t *testing.T) {
	for _, which := range []string{"sender", "multicast", "trunc", "ctrunc", "header-pid-zero", "wrong-seq", "wrong-version", "wrong-resid", "dump-intr", "dump-filtered", "overrun", "unknown-type", "positive-errno", "errno-outside-linux-range", "wrong-ack-header", "short-ack", "duplicate-gen", "duplicate-ack", "gen-done", "gen-unknown-attr", "gen-duplicate-attr", "gen-short-nla", "gen-nested", "gen-endian", "junk-after-terminal"} {
		t.Run(which, func(t *testing.T) {
			d := backendNFTTestDecoder(t, backendNFTGetGen, nil)
			data := append(backendNFTTestGen(), backendNFTTestACK(d.request, 0)...)
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
			case "header-pid-zero":
				binary.NativeEndian.PutUint32(data[12:], 0)
			case "wrong-seq":
				binary.NativeEndian.PutUint32(data[8:], 18)
			case "wrong-version":
				data[17] = 1
			case "wrong-resid":
				data[19] = 24
			case "dump-intr":
				binary.NativeEndian.PutUint16(data[6:], 0x10)
			case "dump-filtered":
				binary.NativeEndian.PutUint16(data[6:], 0x20)
			case "overrun":
				binary.NativeEndian.PutUint16(data[4:], 4)
			case "unknown-type":
				binary.NativeEndian.PutUint16(data[4:], 0x0a7f)
			case "positive-errno":
				packet.Data = backendNFTTestACK(d.request, 22)
			case "errno-outside-linux-range":
				packet.Data = backendNFTTestACK(d.request, -2147483648)
			case "wrong-ack-header":
				data[len(backendNFTTestGen())+24] ^= 1
			case "short-ack":
				packet.Data = backendNFTTestFrame(2, 0, make([]byte, 4))
			case "duplicate-gen":
				packet.Data = append(backendNFTTestGen(), data...)
			case "duplicate-ack":
				packet.Data = append(backendNFTTestACK(d.request, 0), data...)
			case "gen-done":
				packet.Data = backendNFTTestDone()
			case "gen-unknown-attr":
				binary.NativeEndian.PutUint16(data[22:], 2)
			case "gen-duplicate-attr":
				packet.Data = backendNFTTestFrame(backendNFTNewGen, 0, append(backendNFTTestGen()[16:], backendNFTTestAttr(1, backendNFTTestU32(23))...))
			case "gen-short-nla":
				binary.NativeEndian.PutUint16(data[20:], 3)
			case "gen-nested":
				binary.NativeEndian.PutUint16(data[22:], 0x8001)
			case "gen-endian":
				copy(data[24:28], []byte{23, 0, 0, 0})
			case "junk-after-terminal":
				packet.Data = append(data, 0)
			}
			if err := d.consume(packet); err == nil && d.finish() == nil {
				t.Fatalf("%s accepted", which)
			}
		})
	}
}

func TestBackendNFTRejectsMalformedDumpAndExtensions(t *testing.T) {
	for _, which := range []string{"ack-instead-of-done", "ack-after-done", "negative-done", "short-done", "duplicate-done", "no-terminal", "unknown-family", "changed-generation", "bad-padding", "unknown-table-attr", "duplicate-table", "name-no-nul", "name-embedded-nul", "unknown-table-flags", "duplicate-nla", "attr-nested", "name-be-flag", "dump-interrupted", "dump-filtered"} {
		t.Run(which, func(t *testing.T) {
			d := backendNFTTestDecoder(t, backendNFTGetTable, nil)
			table := backendNFTTestTable(7)
			done := backendNFTTestDone()
			data := append(append([]byte(nil), table...), done...)
			switch which {
			case "ack-instead-of-done":
				data = backendNFTTestACK(d.request, 0)
			case "ack-after-done":
				data = append(done, backendNFTTestACK(d.request, 0)...)
			case "negative-done":
				binary.NativeEndian.PutUint32(data[len(table)+16:], ^uint32(0))
			case "short-done":
				data = backendNFTTestFrame(3, 2, nil)
			case "duplicate-done":
				data = append(done, done...)
			case "no-terminal":
				data = table
			case "unknown-family":
				data[16] = 99
			case "changed-generation":
				data[19] = 24
			case "bad-padding":
				// A short NAME attribute with explicit nonzero alignment padding.
				body := append([]byte{7, 0, 0, 23}, backendNFTTestAttr(1, []byte{'x', 0})...)
				body[10] = 1
				data = backendNFTTestFrame(backendNFTNewTable, 2, body)
			case "unknown-table-attr":
				binary.NativeEndian.PutUint16(data[22:], 4)
			case "duplicate-table":
				data = append(append(table, table...), done...)
			case "name-no-nul":
				data[31] = 'x'
			case "name-embedded-nul":
				data[25] = 0
			case "unknown-table-flags":
				data[39] = 2
			case "duplicate-nla":
				binary.NativeEndian.PutUint16(data[42:], 2)
			case "attr-nested":
				binary.NativeEndian.PutUint16(data[34:], 0x8002)
			case "name-be-flag":
				binary.NativeEndian.PutUint16(data[22:], 0x4001)
			case "dump-interrupted":
				binary.NativeEndian.PutUint16(data[6:], 0x12)
			case "dump-filtered":
				binary.NativeEndian.PutUint16(data[len(table)+6:], 0x22)
			}
			if err := d.consume(backendNFTTestPacket(data)); err == nil && d.finish() == nil {
				t.Fatalf("%s accepted", which)
			}
		})
	}
}

func TestBackendNFTAggregateBoundsAndKnownBEFlag(t *testing.T) {
	for _, budget := range []backendNFTBudget{{bytes: backendNFTMaxBytes}, {datagrams: backendNFTMaxDatagrams}, {frames: backendNFTMaxFrames}} {
		d := backendNFTTestDecoder(t, backendNFTGetGen, &budget)
		if err := d.consume(backendNFTTestPacket(backendNFTTestGen())); err == nil {
			t.Fatalf("aggregate ignored: %+v", budget)
		}
	}
	budget := &backendNFTBudget{}
	for range 3 {
		backendNFTTestDecoder(t, backendNFTGetGen, budget)
	}
	request, _ := backendNFTRequest(backendNFTGetGen, 19, 2345)
	if _, err := newBackendNFTDecoder(request, 0, budget); err == nil {
		t.Fatal("fourth request accepted")
	}
	d := backendNFTTestDecoder(t, backendNFTGetGen, nil)
	if err := d.consume(backendNFTTestPacket(make([]byte, backendNFTMaxDatagram+1))); err == nil {
		t.Fatal("oversize datagram")
	}
	d = backendNFTTestDecoder(t, backendNFTGetGen, nil)
	data := backendNFTTestGen()
	binary.NativeEndian.PutUint16(data[22:], 0x4001)
	data = append(data, backendNFTTestACK(d.request, 0)...)
	if err := d.consume(backendNFTTestPacket(data)); err != nil || d.finish() != nil {
		t.Fatalf("known integer BE flag refused: %v", err)
	}
}
