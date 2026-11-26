package startuptools

import (
	"bytes"
	"context"
	"debug/elf"
	"encoding/binary"
	"io"
	"path"
	"slices"
	"strings"
)

type imageRole uint8

const (
	entryRole imageRole = iota + 1
	dependencyRole
	loaderRole
)

type elfReview struct {
	interpreter string
	needed      []string
	paths       []string
	programs    int
	typeID      elf.Type
}

type contextAt struct {
	ctx context.Context
	r   io.ReaderAt
}

func (r contextAt) ReadAt(p []byte, off int64) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.r.ReadAt(p, off)
}

// Prevalidate every allocation-driving extent before debug/elf parses it.
// Entry role is checked independently of cached dependency closure. A DSO's
// PT_INTERP is not its loader dependency: only exec of that image uses it.
func inspectELF(ctx context.Context, reader io.ReaderAt, size int64, arch string, role imageRole) (elfReview, error) {
	var zero elfReview
	if ctx == nil || ctx.Err() != nil || size < 64 || size > maxImageBytes || role < entryRole || role > loaderRole {
		return zero, at("ELF_INPUT", nil)
	}
	r := contextAt{ctx: ctx, r: io.NewSectionReader(reader, 0, size)}
	h := make([]byte, 64)
	if _, err := r.ReadAt(h, 0); err != nil || !bytes.Equal(h[:7], []byte{127, 'E', 'L', 'F', 2, 1, 1}) {
		return zero, at("ELF_HEADER", err)
	}
	u16, u32, u64 := binary.LittleEndian.Uint16, binary.LittleEndian.Uint32, binary.LittleEndian.Uint64
	machine := elf.EM_X86_64
	if arch == "arm64" {
		machine = elf.EM_AARCH64
	} else if arch != "amd64" {
		return zero, at("ELF_ARCH", nil)
	}
	typeID := elf.Type(u16(h[16:18]))
	if (typeID != elf.ET_EXEC && typeID != elf.ET_DYN) || u16(h[18:20]) != uint16(machine) || u32(h[20:24]) != 1 || u16(h[52:54]) != 64 || role != entryRole && typeID != elf.ET_DYN {
		return zero, at("ELF_TARGET", nil)
	}
	ph, sh, pn, sn := u64(h[32:40]), u64(h[40:48]), u16(h[56:58]), u16(h[60:62])
	within := func(off, n uint64) bool { return off <= uint64(size) && n <= uint64(size)-off }
	if pn > 128 || sn > 512 || (pn != 0 && u16(h[54:56]) != 56) || (sn != 0 && u16(h[58:60]) != 64) || sn == 0 && sh != 0 || sn != 0 && u16(h[62:64]) >= sn || !within(ph, uint64(pn)*56) || !within(sh, uint64(sn)*64) {
		return zero, at("ELF_TABLES", nil)
	}
	dynamicPrograms, dynamicSections, interpreters := 0, 0, 0
	var dynamicOffset, dynamicSize uint64
	var interpreter string
	for i := uint16(0); i < pn; i++ {
		p := make([]byte, 56)
		if _, err := r.ReadAt(p, int64(ph)+int64(i)*56); err != nil || !within(u64(p[8:16]), u64(p[32:40])) {
			return zero, at("ELF_PROGRAM", err)
		}
		switch elf.ProgType(u32(p[:4])) {
		case elf.PT_DYNAMIC:
			dynamicPrograms++
			dynamicOffset, dynamicSize = u64(p[8:16]), u64(p[32:40])
		case elf.PT_INTERP:
			interpreters++
			if interpreters > 1 || u64(p[32:40]) < 2 || u64(p[32:40]) > 256 {
				return zero, at("ELF_INTERPRETER_FORM", nil)
			}
			data := make([]byte, int(u64(p[32:40])))
			if _, err := r.ReadAt(data, int64(u64(p[8:16]))); err != nil || data[len(data)-1] != 0 || bytes.IndexByte(data[:len(data)-1], 0) >= 0 {
				return zero, at("ELF_INTERPRETER_FORM", err)
			}
			interpreter = string(data[:len(data)-1])
			if !path.IsAbs(interpreter) || path.Clean(interpreter) != interpreter {
				return zero, at("ELF_INTERPRETER_FORM", nil)
			}
		}
	}
	if role == entryRole && interpreters != 1 || role == loaderRole && interpreters != 0 {
		return zero, at("ELF_ROLE", nil)
	}
	for i := uint16(0); i < sn; i++ {
		s := make([]byte, 64)
		if _, err := r.ReadAt(s, int64(sh)+int64(i)*64); err != nil {
			return zero, at("ELF_SECTION", err)
		}
		t, off, length := elf.SectionType(u32(s[4:8])), u64(s[24:32]), u64(s[32:40])
		if u64(s[8:16])&uint64(elf.SHF_COMPRESSED) != 0 || t != elf.SHT_NOBITS && !within(off, length) || t == elf.SHT_STRTAB && length > 1<<20 {
			return zero, at("ELF_SECTION_BOUNDS", nil)
		}
		if t == elf.SHT_DYNAMIC {
			dynamicSections++
			if off != dynamicOffset || length != dynamicSize || length > 64<<10 || length%16 != 0 || u64(s[56:64]) != 16 || u32(s[40:44]) >= uint32(sn) {
				return zero, at("ELF_DYNAMIC", nil)
			}
			linked := make([]byte, 64)
			if _, err := r.ReadAt(linked, int64(sh)+int64(u32(s[40:44]))*64); err != nil || elf.SectionType(u32(linked[4:8])) != elf.SHT_STRTAB || u64(linked[32:40]) == 0 || u64(linked[32:40]) > 1<<20 || !within(u64(linked[24:32]), u64(linked[32:40])) {
				return zero, at("ELF_DYNAMIC_STRINGS", err)
			}
		}
	}
	if dynamicPrograms != 1 || dynamicPrograms != dynamicSections {
		return zero, at("ELF_DYNAMIC", nil)
	}
	if index := u16(h[62:64]); index != 0 {
		linked := make([]byte, 64)
		if _, err := r.ReadAt(linked, int64(sh)+int64(index)*64); err != nil || elf.SectionType(u32(linked[4:8])) != elf.SHT_STRTAB || u64(linked[32:40]) > 1<<20 || !within(u64(linked[24:32]), u64(linked[32:40])) {
			return zero, at("ELF_SECTION_NAMES", err)
		}
	}
	e, err := elf.NewFile(r)
	if err != nil {
		return zero, at("ELF_PARSE", err)
	}
	defer e.Close()
	for _, tag := range []elf.DynTag{elf.DT_AUDIT, elf.DT_DEPAUDIT, elf.DT_FILTER, elf.DT_AUXILIARY} {
		values, err := e.DynValue(tag)
		if err != nil || len(values) != 0 {
			return zero, at("ELF_LOADER_OVERRIDE", err)
		}
	}
	var paths []string
	for _, tag := range []elf.DynTag{elf.DT_RPATH, elf.DT_RUNPATH} {
		values, err := e.DynString(tag)
		if err != nil || len(values) > 1 {
			return zero, at("ELF_SEARCH", err)
		}
		for _, value := range values {
			parts := strings.Split(value, ":")
			if len(parts) > 8 || len(value) > 1024 {
				return zero, at("ELF_SEARCH", nil)
			}
			paths = append(paths, parts...)
		}
	}
	needed, err := e.ImportedLibraries()
	if err != nil || len(needed) > 32 {
		return zero, at("ELF_DEPENDENCIES", err)
	}
	for _, name := range needed {
		if !libraryName(name) {
			return zero, at("ELF_DEPENDENCY_NAME", nil)
		}
	}
	if ctx.Err() != nil {
		return zero, at("ELF_CONTEXT", ctx.Err())
	}
	return elfReview{interpreter: interpreter, needed: needed, paths: paths, programs: interpreters, typeID: typeID}, nil
}

func libraryName(name string) bool {
	if name == "" || len(name) > 128 || name == "." || name == ".." {
		return false
	}
	for _, c := range name {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("._+-", c)) {
			return false
		}
	}
	return true
}
func permittedSearch(p profile, paths []string) bool {
	// Every admitted RPATH/RUNPATH has the same precedence as the fixed
	// explicit LD_LIBRARY_PATH prefix. No cache/default-directory fallback.
	if len(paths) == 0 {
		return true
	}
	for _, value := range paths {
		if !slices.Contains(p.libraries, value) {
			return false
		}
	}
	return slices.Equal(paths, p.libraries[:min(len(paths), len(p.libraries))])
}
func joinPaths(paths []string) string { return strings.Join(paths, ":") }
