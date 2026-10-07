package netidentity

import (
	"bytes"
	"context"
	"debug/elf"
	"encoding/binary"
	"io"
	"testing"
)

// Test-only fact probe; no ELF policy, acceptance or identity issuer.
// Report NOBITS memory size versus file size without treating it as a fault.
func qaNoBitsOverFile(ctx context.Context, reader io.ReaderAt, size int64) (known, overFile bool) {
	if ctx == nil || ctx.Err() != nil || size < 64 || size > 16<<20 {
		return false, false
	}
	r := contextReaderAt{ctx, io.NewSectionReader(reader, 0, size)}
	h := make([]byte, 64)
	if _, err := r.ReadAt(h, 0); err != nil || !bytes.Equal(h[:7], []byte{0x7f, 'E', 'L', 'F', 2, 1, 1}) {
		return false, false
	}
	u16, u32, u64 := binary.LittleEndian.Uint16, binary.LittleEndian.Uint32, binary.LittleEndian.Uint64
	offset, count := u64(h[40:48]), u16(h[60:62])
	if count == 0 || count > 256 || u16(h[58:60]) != 64 || offset > uint64(size) || uint64(count)*64 > uint64(size)-offset {
		return false, false
	}
	for n := uint16(0); n < count; n++ {
		s := make([]byte, 64)
		if _, err := r.ReadAt(s, int64(offset)+int64(n)*64); err != nil {
			return false, false
		}
		if u32(s[4:8]) == uint32(elf.SHT_NOBITS) && u64(s[32:40]) > uint64(size) {
			overFile = true
		}
	}
	return ctx.Err() == nil, overFile
}

func TestQANoBitsProbeIsBoundedAndFollowsMemorySemantics(t *testing.T) {
	raw := elfModel()
	if known, over := qaNoBitsOverFile(context.Background(), bytes.NewReader(raw), int64(len(raw))); !known || over {
		t.Fatal("absent NOBITS predicate")
	}
	withBSS := elfBSSModel()
	if known, over := qaNoBitsOverFile(context.Background(), bytes.NewReader(withBSS), int64(len(withBSS))); !known || !over {
		t.Fatal("NOBITS/file-size predicate lost")
	}
	e, err := boundedELF(context.Background(), bytes.NewReader(withBSS), int64(len(withBSS)))
	if err != nil {
		t.Fatal("memory-only size is not a file extent", err)
	}
	_ = e.Close()
	binary.LittleEndian.PutUint64(withBSS[40:], 1<<62)
	if known, _ := qaNoBitsOverFile(context.Background(), bytes.NewReader(withBSS), int64(len(withBSS))); known {
		t.Fatal("out-of-bounds table accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if known, _ := qaNoBitsOverFile(ctx, bytes.NewReader(raw), int64(len(raw))); known {
		t.Fatal("cancelled probe")
	}
}
