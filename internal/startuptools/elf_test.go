package startuptools

import (
	"bytes"
	"context"
	"debug/elf"
	"encoding/binary"
	"strings"
	"testing"
)

// Synthetic ELF data, never an executable fixture or production issuer.
func elfFixture(interpreter string, needed []string) []byte {
	pn := 1
	if interpreter != "" {
		pn++
	}
	sh := 64 + pn*56
	dynamic := sh + 4*64
	stringsAt := dynamic + (len(needed)+1)*16
	str := []byte{0}
	var offsets []int
	for _, name := range needed {
		offsets = append(offsets, len(str))
		str = append(str, []byte(name)...)
		str = append(str, 0)
	}
	interpreterAt := stringsAt + len(str)
	raw := make([]byte, interpreterAt)
	if interpreter != "" {
		raw = append(raw, []byte(interpreter)...)
		raw = append(raw, 0)
	}
	copy(raw, []byte{127, 'E', 'L', 'F', 2, 1, 1})
	u16, u32, u64 := binary.LittleEndian.PutUint16, binary.LittleEndian.PutUint32, binary.LittleEndian.PutUint64
	u16(raw[16:], uint16(elf.ET_DYN))
	u16(raw[18:], uint16(elf.EM_AARCH64))
	u32(raw[20:], 1)
	u64(raw[32:], 64)
	u64(raw[40:], uint64(sh))
	u16(raw[52:], 64)
	u16(raw[54:], 56)
	u16(raw[56:], uint16(pn))
	u16(raw[58:], 64)
	u16(raw[60:], 4)
	u32(raw[64:], uint32(elf.PT_DYNAMIC))
	u64(raw[72:], uint64(dynamic))
	u64(raw[96:], uint64((len(needed)+1)*16))
	if interpreter != "" {
		u32(raw[120:], uint32(elf.PT_INTERP))
		u64(raw[128:], uint64(interpreterAt))
		u64(raw[152:], uint64(len(interpreter)+1))
	}
	d := sh + 64
	u32(raw[d+4:], uint32(elf.SHT_DYNAMIC))
	u64(raw[d+24:], uint64(dynamic))
	u64(raw[d+32:], uint64((len(needed)+1)*16))
	u32(raw[d+40:], 2)
	u64(raw[d+56:], 16)
	s := sh + 128
	u32(raw[s+4:], uint32(elf.SHT_STRTAB))
	u64(raw[s+24:], uint64(stringsAt))
	u64(raw[s+32:], uint64(len(str)))
	u64(raw[s+48:], 1)
	bss := sh + 192
	u32(raw[bss+4:], uint32(elf.SHT_NOBITS))
	u64(raw[bss+24:], uint64(len(raw)))
	u64(raw[bss+32:], 32<<20)
	for i, off := range offsets {
		u64(raw[dynamic+i*16:], uint64(elf.DT_NEEDED))
		u64(raw[dynamic+i*16+8:], uint64(off))
	}
	copy(raw[stringsAt:], str)
	return raw
}

func TestELFDependencyInterpreterDoesNotBecomeExecLoader(t *testing.T) {
	raw := elfFixture("/lib/absent-standalone-libc-loader", []string{"libc.so.6"})
	meta, err := inspectELF(context.Background(), bytes.NewReader(raw), int64(len(raw)), "arm64", dependencyRole)
	if err != nil || meta.interpreter != "/lib/absent-standalone-libc-loader" || len(meta.needed) != 1 {
		t.Fatal("well-formed DSO standalone interpreter was refused", err)
	}
	// Role validation must run again even when an image was parsed as a DSO.
	noInterpreter := elfFixture("", nil)
	if _, err := inspectELF(context.Background(), bytes.NewReader(noInterpreter), int64(len(noInterpreter)), "arm64", dependencyRole); err != nil {
		t.Fatal(err)
	}
	if _, err := inspectELF(context.Background(), bytes.NewReader(noInterpreter), int64(len(noInterpreter)), "arm64", entryRole); err == nil {
		t.Fatal("DSO role was promoted into entry role without its interpreter")
	}
	if _, err := inspectELF(context.Background(), bytes.NewReader(raw), int64(len(raw)), "arm64", loaderRole); err == nil {
		t.Fatal("a loader with its own interpreter was accepted")
	}
}

type countedAt struct {
	reader *bytes.Reader
	bytes  int
}

func (r *countedAt) ReadAt(data []byte, offset int64) (int, error) {
	n, err := r.reader.ReadAt(data, offset)
	r.bytes += n
	return n, err
}

func TestELFAllocationBoundsAndMemoryOnlyBSS(t *testing.T) {
	raw := elfFixture("/opt/lib/ld-linux-aarch64.so.1", []string{"libc.so.6"})
	r := &countedAt{reader: bytes.NewReader(raw)}
	if _, err := inspectELF(context.Background(), r, int64(len(raw)), "arm64", entryRole); err != nil || r.bytes > 8192 {
		t.Fatal("memory-only BSS caused unbounded reads", err, r.bytes)
	}
	for _, fault := range []string{"program-count", "section-count", "program-outside", "section-outside", "compressed", "string-allocation", "dynamic-allocation", "dynamic-nobits-link", "section-name-nobits", "wrong-machine", "wrong-endian", "relative-interpreter"} {
		t.Run(fault, func(t *testing.T) {
			bad := bytes.Clone(raw)
			sh := int(binary.LittleEndian.Uint64(bad[40:]))
			switch fault {
			case "program-count":
				binary.LittleEndian.PutUint16(bad[56:], 65535)
			case "section-count":
				binary.LittleEndian.PutUint16(bad[60:], 65535)
			case "program-outside":
				binary.LittleEndian.PutUint64(bad[72:], 1<<63)
			case "section-outside":
				binary.LittleEndian.PutUint64(bad[sh+128+24:], uint64(len(bad)))
			case "compressed":
				binary.LittleEndian.PutUint64(bad[sh+128+8:], uint64(elf.SHF_COMPRESSED))
			case "string-allocation":
				binary.LittleEndian.PutUint64(bad[sh+128+32:], 2<<20)
			case "dynamic-allocation":
				binary.LittleEndian.PutUint64(bad[sh+64+32:], 128<<10)
			case "dynamic-nobits-link":
				binary.LittleEndian.PutUint32(bad[sh+64+40:], 3)
			case "section-name-nobits":
				binary.LittleEndian.PutUint16(bad[62:], 3)
			case "wrong-machine":
				binary.LittleEndian.PutUint16(bad[18:], uint16(elf.EM_X86_64))
			case "wrong-endian":
				bad[5] = 2
			case "relative-interpreter":
				off := binary.LittleEndian.Uint64(bad[128:])
				bad[off] = '.'
			}
			if _, err := inspectELF(context.Background(), bytes.NewReader(bad), int64(len(bad)), "arm64", entryRole); err == nil {
				t.Fatal("malformed ELF accepted")
			}
		})
	}
	c, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := inspectELF(c, bytes.NewReader(raw), int64(len(raw)), "arm64", entryRole); err == nil {
		t.Fatal("cancelled ELF review succeeded")
	}
}

func TestDependencyNamesAndFixedSearchPolicy(t *testing.T) {
	for _, name := range []string{"", ".", "..", "../libc.so.6", "lib/escape", "$ORIGIN", strings.Repeat("a", 129)} {
		raw := elfFixture("", []string{name})
		if _, err := inspectELF(context.Background(), bytes.NewReader(raw), int64(len(raw)), "arm64", dependencyRole); err == nil {
			t.Fatal("unsafe dependency accepted", name)
		}
	}
	if libraryName("libc.so\x00") {
		t.Fatal("literal NUL accepted in a dependency name")
	}
	p := stockProfile()
	if !permittedSearch(p, []string{"/opt/lib"}) || permittedSearch(p, []string{"/lib", "/opt/lib"}) || permittedSearch(p, []string{"$ORIGIN"}) || permittedSearch(p, []string{"/tmp"}) {
		t.Fatal("loader precedence was not kept fixed")
	}
}
