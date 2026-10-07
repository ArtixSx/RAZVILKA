package netidentity

import (
	"bytes"
	"context"
	"debug/elf"
	"encoding/binary"
	"io"
)

type contextReaderAt struct {
	ctx context.Context
	r   io.ReaderAt
}

func (r contextReaderAt) ReadAt(b []byte, offset int64) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.r.ReadAt(b, offset)
}

// Check table extents before debug/elf can allocate from section metadata.
// Extended numbering, compressed sections and ambiguous dynamic tables refuse.
func boundedELF(ctx context.Context, reader io.ReaderAt, size int64) (*elf.File, error) {
	if ctx == nil || ctx.Err() != nil || size < 64 || size > 16<<20 {
		return nil, ErrUnknown
	}
	r := contextReaderAt{ctx, io.NewSectionReader(reader, 0, size)}
	h := make([]byte, 64)
	if _, err := r.ReadAt(h, 0); err != nil || !bytes.Equal(h[:7], []byte{0x7f, 'E', 'L', 'F', 2, 1, 1}) {
		return nil, ErrUnknown
	}
	u16, u32, u64 := binary.LittleEndian.Uint16, binary.LittleEndian.Uint32, binary.LittleEndian.Uint64
	if (u16(h[16:18]) != uint16(elf.ET_EXEC) && u16(h[16:18]) != uint16(elf.ET_DYN)) || u16(h[18:20]) != uint16(elf.EM_AARCH64) || u32(h[20:24]) != 1 || u16(h[52:54]) != 64 {
		return nil, ErrUnknown
	}
	ph, sh := u64(h[32:40]), u64(h[40:48])
	pn, sn := u16(h[56:58]), u16(h[60:62])
	if pn > 128 || sn > 256 || (pn != 0 && u16(h[54:56]) != 56) || (sn != 0 && u16(h[58:60]) != 64) ||
		(sn == 0 && sh != 0) || (sn != 0 && u16(h[62:64]) >= sn) {
		return nil, ErrUnknown
	}
	within := func(offset, count uint64) bool { return offset <= uint64(size) && count <= uint64(size)-offset }
	if !within(ph, uint64(pn)*56) || !within(sh, uint64(sn)*64) {
		return nil, ErrUnknown
	}
	var dynamicOffset, dynamicSize uint64
	dynamicPrograms, dynamicSections := 0, 0
	for n := uint16(0); n < pn; n++ {
		p := make([]byte, 56)
		if _, err := r.ReadAt(p, int64(ph)+int64(n)*56); err != nil || !within(u64(p[8:16]), u64(p[32:40])) {
			return nil, ErrUnknown
		}
		if u32(p[:4]) == uint32(elf.PT_DYNAMIC) {
			dynamicPrograms++
			dynamicOffset, dynamicSize = u64(p[8:16]), u64(p[32:40])
		}
	}
	for n := uint16(0); n < sn; n++ {
		s := make([]byte, 64)
		if _, err := r.ReadAt(s, int64(sh)+int64(n)*64); err != nil {
			return nil, ErrUnknown
		}
		offset, length := u64(s[24:32]), u64(s[32:40])
		if u64(s[8:16])&uint64(elf.SHF_COMPRESSED) != 0 || length > uint64(size) || (u32(s[4:8]) != uint32(elf.SHT_NOBITS) && !within(offset, length)) {
			return nil, ErrUnknown
		}
		if u32(s[4:8]) == uint32(elf.SHT_DYNAMIC) {
			dynamicSections++
			if offset != dynamicOffset || length != dynamicSize || length > 64<<10 || length%16 != 0 || u64(s[56:64]) != 16 {
				return nil, ErrUnknown
			}
		}
	}
	if dynamicPrograms > 1 || dynamicPrograms != dynamicSections {
		return nil, ErrUnknown
	}
	e, err := elf.NewFile(r)
	if err != nil || ctx.Err() != nil {
		if e != nil {
			_ = e.Close()
		}
		return nil, ErrUnknown
	}
	for _, tag := range []elf.DynTag{elf.DT_RPATH, elf.DT_RUNPATH, elf.DT_AUDIT, elf.DT_DEPAUDIT, elf.DT_FILTER, elf.DT_AUXILIARY} {
		values, err := e.DynValue(tag)
		if err != nil || len(values) != 0 {
			_ = e.Close()
			return nil, ErrUnknown
		}
	}
	return e, nil
}
