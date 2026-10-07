package netidentity

import (
	"bytes"
	"context"
	"debug/elf"
	"encoding/binary"
	"testing"
)

func elfModel() []byte {
	raw := make([]byte, 64+56+2*64+16)
	copy(raw, []byte{0x7f, 'E', 'L', 'F', 2, 1, 1})
	binary.LittleEndian.PutUint16(raw[16:], uint16(elf.ET_DYN))
	binary.LittleEndian.PutUint16(raw[18:], uint16(elf.EM_AARCH64))
	binary.LittleEndian.PutUint32(raw[20:], 1)
	binary.LittleEndian.PutUint64(raw[32:], 64)
	binary.LittleEndian.PutUint64(raw[40:], 120)
	binary.LittleEndian.PutUint16(raw[52:], 64)
	binary.LittleEndian.PutUint16(raw[54:], 56)
	binary.LittleEndian.PutUint16(raw[56:], 1)
	binary.LittleEndian.PutUint16(raw[58:], 64)
	binary.LittleEndian.PutUint16(raw[60:], 2)
	binary.LittleEndian.PutUint32(raw[64:], uint32(elf.PT_DYNAMIC))
	binary.LittleEndian.PutUint64(raw[72:], 248)
	binary.LittleEndian.PutUint64(raw[96:], 16)
	binary.LittleEndian.PutUint32(raw[188:], uint32(elf.SHT_DYNAMIC))
	binary.LittleEndian.PutUint64(raw[208:], 248)
	binary.LittleEndian.PutUint64(raw[216:], 16)
	binary.LittleEndian.PutUint64(raw[240:], 16)
	return raw
}

func TestBoundedSystemELFMetadataAndForbiddenTags(t *testing.T) {
	raw := elfModel()
	e, err := boundedELF(context.Background(), bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		t.Fatal("absent non-string tags refused", err)
	}
	_ = e.Close()
	for _, fault := range []string{"extent", "compressed", "dynamic-size", "missing-dynamic-section", "machine", "audit", "rpath", "extended-count"} {
		bad := bytes.Clone(raw)
		switch fault {
		case "extent":
			binary.LittleEndian.PutUint64(bad[40:], 1<<62)
		case "compressed":
			binary.LittleEndian.PutUint64(bad[192:], uint64(elf.SHF_COMPRESSED))
		case "dynamic-size":
			binary.LittleEndian.PutUint64(bad[216:], 1<<62)
		case "missing-dynamic-section":
			binary.LittleEndian.PutUint32(bad[188:], uint32(elf.SHT_NULL))
		case "machine":
			binary.LittleEndian.PutUint16(bad[18:], uint16(elf.EM_X86_64))
		case "audit":
			binary.LittleEndian.PutUint64(bad[248:], uint64(elf.DT_AUDIT))
		case "rpath":
			binary.LittleEndian.PutUint64(bad[248:], uint64(elf.DT_RPATH))
		case "extended-count":
			binary.LittleEndian.PutUint16(bad[60:], 0)
		}
		if e, err := boundedELF(context.Background(), bytes.NewReader(bad), int64(len(bad))); err == nil {
			_ = e.Close()
			t.Fatal("unsafe ELF accepted", fault)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := boundedELF(ctx, bytes.NewReader(raw), int64(len(raw))); err == nil {
		t.Fatal("cancelled read")
	}
}
