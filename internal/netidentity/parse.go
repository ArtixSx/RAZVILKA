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
	names := []string{}
	seen := map[string]bool{}
	unknown, dot, dotdot := false, false, false
	buf := make([]byte, 4096)
	total := 0
	var cookie uint64
	for calls := 0; calls < maxDirectoryCalls; calls++ {
		if ctx.Err() != nil || total >= maxDirectoryBytes {
			return names, unknown, false, false
		}
		chunk := buf
		if remaining := maxDirectoryBytes - total; remaining < len(chunk) {
			chunk = chunk[:remaining]
		}
		n, err := read(chunk)
		if err != nil || n < 0 || n > len(chunk) {
			return names, unknown, false, false
		}
		if n == 0 {
			return names, unknown, true, dot && dotdot
		}
		total += n
		for off := 0; off < n; {
			if n-off < 20 {
				return names, unknown, false, false
			}
			recordLength := int(binary.LittleEndian.Uint16(chunk[off+16 : off+18]))
			if recordLength < 24 || recordLength%8 != 0 || recordLength > n-off {
				return names, unknown, false, false
			}
			record := chunk[off : off+recordLength]
			next := binary.LittleEndian.Uint64(record[8:16])
			if next != cookie+1 {
				return names, unknown, false, false
			}
			cookie = next
			end := bytes.IndexByte(record[19:], 0)
			if end < 1 || end > 64 {
				return names, unknown, false, false
			}
			name := string(record[19 : 19+end])
			if seen[name] {
				return names, unknown, false, false
			}
			seen[name] = true
			switch name {
			case ".":
				if cookie != 1 {
					return names, unknown, false, false
				}
				dot = true
			case "..":
				if cookie != 2 {
					return names, unknown, false, false
				}
				dotdot = true
			default:
				if !dot || !dotdot || len(names) >= maxNames {
					return names, unknown, false, false
				}
				for i := 0; i < len(name); i++ {
					b := name[i]
					if !((b >= 'a' && b <= 'z') || (b >= '0' && b <= '9') || b == '_') {
						return names, unknown, false, false
					}
				}
				names = append(names, name)
				if record[18] == 0 {
					unknown = true
				}
			}
			off += recordLength
		}
	}
	return names, unknown, false, false
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
	for _, line := range lines {
		if len(line) > 65536 {
			return false
		}
		fields := strings.Fields(line)
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

func mountUnescape(s string) (string, bool) {
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
