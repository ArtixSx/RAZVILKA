package dataplane

import (
	"encoding/binary"
	"io"
	"runtime"
)

// Read a fixed ELF64 header and bounded program table, rather than allocating
// according to section offsets/counts supplied by an executable image. This
// comparison neither opens a caller path nor admits execution.
func xraySelectedTCPELFHeader(reader io.ReaderAt, size int64) error {
	if reader == nil || size < 64 || size > 128<<20 {
		return errXraySelectedTCPRuntime
	}
	var header [64]byte
	if n, err := reader.ReadAt(header[:], 0); err != nil || n != len(header) ||
		string(header[:4]) != "\x7fELF" || header[4] != 2 || header[5] != 1 || header[6] != 1 {
		return errXraySelectedTCPRuntime
	}
	le := binary.LittleEndian
	machine := uint16(0)
	switch runtime.GOARCH {
	case "amd64":
		machine = 62
	case "arm64":
		machine = 183
	}
	kind := le.Uint16(header[16:18])
	entry := le.Uint64(header[24:32])
	offset := le.Uint64(header[32:40])
	count := uint64(le.Uint16(header[56:58]))
	if machine == 0 || le.Uint16(header[18:20]) != machine || le.Uint32(header[20:24]) != 1 ||
		kind != 2 && kind != 3 || entry == 0 || le.Uint16(header[52:54]) != 64 || le.Uint16(header[54:56]) != 56 ||
		count == 0 || count > 1024 || offset < 64 || offset > uint64(size) || count*56 > uint64(size)-offset {
		return errXraySelectedTCPRuntime
	}
	entryMapped := false
	var program [56]byte
	for i := uint64(0); i < count; i++ {
		if n, err := reader.ReadAt(program[:], int64(offset+i*56)); err != nil || n != len(program) {
			return errXraySelectedTCPRuntime
		}
		if le.Uint32(program[:4]) != 1 {
			continue
		}
		fileOffset := le.Uint64(program[8:16])
		address := le.Uint64(program[16:24])
		fileSize, memorySize := le.Uint64(program[32:40]), le.Uint64(program[40:48])
		if fileSize > memorySize || fileOffset > uint64(size) || fileSize > uint64(size)-fileOffset || address > ^uint64(0)-memorySize {
			return errXraySelectedTCPRuntime
		}
		entryMapped = entryMapped || le.Uint32(program[4:8])&1 != 0 && entry >= address && entry-address < fileSize
	}
	if !entryMapped {
		return errXraySelectedTCPRuntime
	}
	return nil
}
