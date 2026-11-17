package netidentity

import (
	"bytes"
	"context"
	"encoding/binary"
	"strconv"
	"strings"
)

const (
	maxMountBytes     = 256 * 1024
	maxDirectoryBytes = 64 * 1024
	maxDirectoryCalls = 64
	maxNames          = 64
)

// linux_dirent64 has the same byte layout on little-endian amd64 and arm64.
// Parse raw records directly: syscall.ParseDirent would skip d_ino == 0 records.
// d_type never decides whether a namespace name is kept, including DT_UNKNOWN.
func readNamespaceDirectory(ctx context.Context, read func([]byte) (int, error)) ([]string, bool, bool, bool) {
	state := newNamespaceDirectoryState()
	buf := make([]byte, 4096)
	total := 0
	for calls := 0; calls < maxDirectoryCalls; calls++ {
		if ctx.Err() != nil || total >= maxDirectoryBytes {
			return state.names, state.unknown, false, false
		}
		chunk := buf
		if remaining := maxDirectoryBytes - total; remaining < len(chunk) {
			chunk = chunk[:remaining]
		}
		n, err := read(chunk)
		if err != nil || n < 0 || n > len(chunk) {
			return state.names, state.unknown, false, false
		}
		if n == 0 {
			return state.names, state.unknown, true, state.dot && state.dotdot
		}
		total += n
		if !state.consume(chunk, n) {
			return state.names, state.unknown, false, false
		}
	}
	return state.names, state.unknown, false, false
}

type namespaceDirectoryState struct {
	names                []string
	seen                 map[string]bool
	unknown, dot, dotdot bool
	cookie               uint64
}

func newNamespaceDirectoryState() namespaceDirectoryState {
	return namespaceDirectoryState{names: []string{}, seen: map[string]bool{}}
}

// consume owns every returned name; raw input may be reused after this call.
// Failure retains the same partial names, type, dot and cookie state.
func (s *namespaceDirectoryState) consume(chunk []byte, n int) bool {
	for off := 0; off < n; {
		if n-off < 20 {
			return false
		}
		recordLength := int(binary.LittleEndian.Uint16(chunk[off+16 : off+18]))
		if recordLength < 24 || recordLength%8 != 0 || recordLength > n-off {
			return false
		}
		record := chunk[off : off+recordLength]
		next := binary.LittleEndian.Uint64(record[8:16])
		if next != s.cookie+1 {
			return false
		}
		s.cookie = next
		end := bytes.IndexByte(record[19:], 0)
		if end < 1 || end > 64 {
			return false
		}
		name := string(record[19 : 19+end])
		if s.seen[name] {
			return false
		}
		s.seen[name] = true
		switch name {
		case ".":
			if s.cookie != 1 {
				return false
			}
			s.dot = true
		case "..":
			if s.cookie != 2 {
				return false
			}
			s.dotdot = true
		default:
			if !s.dot || !s.dotdot || len(s.names) >= maxNames {
				return false
			}
			for i := 0; i < len(name); i++ {
				b := name[i]
				if !((b >= 'a' && b <= 'z') || (b >= '0' && b <= '9') || b == '_') {
					return false
				}
			}
			s.names = append(s.names, name)
			if record[18] == 0 {
				s.unknown = true
			}
		}
		off += recordLength
	}
	return true
}

func mountLayoutOK(data []byte, rootID uint64, paths []string) bool {
	if len(data) == 0 || data[len(data)-1] != '\n' {
		return false
	}
	rootSeen := false
	lines := strings.Split(string(data[:len(data)-1]), "\n")
	if len(lines) > 8192 {
		return false
	}
	var fieldStorage [16]string
	for _, line := range lines {
		if len(line) > 65536 {
			return false
		}
		fields := mountFields(line, fieldStorage[:0])
		if len(fields) < 10 {
			return false
		}
		id, err := strconv.ParseUint(fields[0], 10, 64)
		if err != nil || id == 0 {
			return false
		}
		separator := -1
		for i := 6; i < len(fields); i++ {
			if fields[i] == "-" {
				separator = i
				break
			}
		}
		if separator < 6 || len(fields) != separator+4 {
			return false
		}
		root, ok := mountUnescape(fields[3])
		if !ok {
			return false
		}
		point, ok := mountUnescape(fields[4])
		if !ok || !strings.HasPrefix(point, "/") {
			return false
		}
		if id == rootID {
			if rootSeen || root != "/" || point != "/proc" || fields[separator+1] != "proc" {
				return false
			}
			rootSeen = true
			continue
		}
		if point != "/proc" && !strings.HasPrefix(point, "/proc/") {
			continue
		}
		for _, path := range paths {
			if path == point || strings.HasPrefix(path, point+"/") ||
				(strings.HasSuffix(path, "/fdinfo") && strings.HasPrefix(point, path+"/")) {
				return false
			}
		}
	}
	return rootSeen
}

// The ordinary ASCII mountinfo line fits this caller-owned scratch. Return
// substrings of the same immutable input, never a retained observation. Long
// optional-field lists and every non-ASCII byte use the original Fields parser
// so Unicode whitespace, malformed UTF-8 and unbounded field counts keep their
// existing meaning. Unlike FieldsSeq, the common path scans each byte once.
func mountFields(line string, fields []string) []string {
	for offset := 0; offset < len(line); {
		if line[offset] >= 0x80 {
			return strings.Fields(line)
		}
		if mountFieldSpace(line[offset]) {
			offset++
			continue
		}
		start := offset
		for offset < len(line) && line[offset] < 0x80 && !mountFieldSpace(line[offset]) {
			offset++
		}
		if offset < len(line) && line[offset] >= 0x80 || len(fields) == cap(fields) {
			return strings.Fields(line)
		}
		fields = append(fields, line[start:offset])
	}
	return fields
}

func mountFieldSpace(b byte) bool {
	return b == ' ' || b >= '\t' && b <= '\r'
}

func mountUnescape(s string) (string, bool) {
	// Plain mount fields need no new storage. The only callers consume this
	// immutable substring inside mountLayoutOK; they never retain it as state.
	if !strings.Contains(s, "\\") {
		return s, true
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' {
			b.WriteByte(s[i])
			continue
		}
		if len(s)-i < 4 {
			return "", false
		}
		var decoded byte
		switch s[i+1 : i+4] {
		case "040":
			decoded = ' '
		case "011":
			decoded = '\t'
		case "012":
			decoded = '\n'
		case "134":
			decoded = '\\'
		default:
			return "", false
		}
		b.WriteByte(decoded)
		i += 3
	}
	return b.String(), true
}
