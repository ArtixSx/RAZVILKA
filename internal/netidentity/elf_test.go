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

// Small file with a loadable 32 MiB memory-only BSS, an empty dynamic table,
// and its actual linked string table. No section-name table is required.
func elfBSSModel() []byte {
	raw := make([]byte, 449)
	copy(raw, elfModel()[:64])
	u16, u32, u64 := binary.LittleEndian.PutUint16, binary.LittleEndian.PutUint32, binary.LittleEndian.PutUint64
	u64(raw[40:], 176)
	u16(raw[56:], 2)
	u16(raw[60:], 4)
	u32(raw[64:], uint32(elf.PT_LOAD))
	u32(raw[68:], uint32(elf.PF_R|elf.PF_W))
	u64(raw[96:], uint64(len(raw)))
	u64(raw[104:], uint64(len(raw))+(32<<20))
	u64(raw[112:], 4096)
	u32(raw[120:], uint32(elf.PT_DYNAMIC))
	u32(raw[124:], uint32(elf.PF_R|elf.PF_W))
	u64(raw[128:], 432)
	u64(raw[136:], 432)
	u64(raw[152:], 16)
	u64(raw[160:], 16)
	u64(raw[168:], 8)
	u32(raw[244:], uint32(elf.SHT_DYNAMIC))
	u64(raw[248:], uint64(elf.SHF_ALLOC|elf.SHF_WRITE))
	u64(raw[256:], 432)
	u64(raw[264:], 432)
	u64(raw[272:], 16)
	u32(raw[280:], 2)
	u64(raw[288:], 8)
	u64(raw[296:], 16)
	u32(raw[308:], uint32(elf.SHT_STRTAB))
	u64(raw[328:], 448)
	u64(raw[336:], 1)
	u64(raw[352:], 1)
	u32(raw[372:], uint32(elf.SHT_NOBITS))
	u64(raw[376:], uint64(elf.SHF_ALLOC|elf.SHF_WRITE))
	u64(raw[384:], 449)
	u64(raw[392:], 449)
	u64(raw[400:], 32<<20)
	u64(raw[416:], 1)
	return raw
}

type elfReadBudget struct {
	reader    *bytes.Reader
	bytes     int
	afterRead func()
}

func (r *elfReadBudget) ReadAt(raw []byte, offset int64) (int, error) {
	n, err := r.reader.ReadAt(raw, offset)
	r.bytes += n
	if r.afterRead != nil {
		r.afterRead()
	}
	return n, err
}

func TestBoundedELFLargeMemoryOnlyBSSAndFileBackedBounds(t *testing.T) {
	raw := elfBSSModel()
	r := &elfReadBudget{reader: bytes.NewReader(raw)}
	e, err := boundedELF(context.Background(), r, int64(len(raw)))
	if err != nil {
		t.Fatal("valid memory-only BSS refused", err)
	}
	defer e.Close()
	libs, err := e.ImportedLibraries()
	if err != nil || len(libs) != 0 || e.Sections[3].Size != 32<<20 {
		t.Fatal("valid dynamic/BSS metadata", err)
	}
	before := r.bytes
	if _, err := e.Sections[3].Open().Read(make([]byte, 1)); err == nil {
		t.Fatal("BSS file read succeeded")
	}
	if r.bytes != before || r.bytes > 4096 {
		t.Fatal("memory extent caused file reads")
	}
	for _, fault := range []string{"file-backed-length", "file-backed-offset", "program-extent", "compressed-bss", "malformed-bss-size", "malformed-bss-offset", "extended-count"} {
		bad := bytes.Clone(raw)
		switch fault {
		case "file-backed-length":
			binary.LittleEndian.PutUint32(bad[372:], uint32(elf.SHT_PROGBITS))
		case "file-backed-offset":
			binary.LittleEndian.PutUint64(bad[328:], uint64(len(raw)))
		case "program-extent":
			binary.LittleEndian.PutUint64(bad[96:], uint64(len(raw)+1))
		case "compressed-bss":
			binary.LittleEndian.PutUint64(bad[376:], uint64(elf.SHF_COMPRESSED))
		case "malformed-bss-size":
			binary.LittleEndian.PutUint64(bad[400:], 1<<63)
		case "malformed-bss-offset":
			binary.LittleEndian.PutUint64(bad[392:], 1<<63)
		case "extended-count":
			binary.LittleEndian.PutUint16(bad[60:], 0)
		}
		if e, err := boundedELF(context.Background(), bytes.NewReader(bad), int64(len(bad))); err == nil {
			_ = e.Close()
			t.Fatal("malformed extent accepted", fault)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r = &elfReadBudget{reader: bytes.NewReader(raw)}
	if _, err := boundedELF(ctx, r, int64(len(raw))); err == nil || r.bytes != 0 {
		t.Fatal("cancelled ELF read")
	}
	ctx, cancel = context.WithCancel(context.Background())
	defer cancel()
	r = &elfReadBudget{reader: bytes.NewReader(raw), afterRead: cancel}
	if _, err := boundedELF(ctx, r, int64(len(raw))); err == nil || r.bytes == 0 || r.bytes >= len(raw) {
		t.Fatal("ELF cancellation between metadata reads ignored")
	}
	if _, err := boundedELF(context.Background(), bytes.NewReader(raw), (16<<20)+1); err == nil {
		t.Fatal("file image cap bypassed")
	}
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
