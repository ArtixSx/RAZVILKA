package netidentity

import (
	"bytes"
	"strings"
)

// This is the reviewed NDMC formatter: right-aligned names at root column17
// and child column21, not nesting inferred from the leading name indentation.
// The only cosmetic envelope is a paired literal erase-line at byte boundaries.
func parseBuild(raw []byte) (buildTuple, error) {
	var v buildTuple
	if len(raw) == 0 || len(raw) > 8192 {
		return v, ErrUnknown
	}
	envelope := []byte("\x1b[K")
	if bytes.HasPrefix(raw, envelope) || bytes.HasSuffix(raw, envelope) {
		if len(raw) < 6 || !bytes.HasPrefix(raw, envelope) || !bytes.HasSuffix(raw, envelope) {
			return v, ErrUnknown
		}
		raw = raw[3 : len(raw)-3]
	}
	for n, b := range raw {
		if b == '\r' && n+1 < len(raw) && raw[n+1] == '\n' {
			continue
		}
		if b != '\n' && (b < 32 || b > 126) {
			return v, ErrUnknown
		}
	}
	if len(raw) == 0 || raw[len(raw)-1] != '\n' {
		return v, ErrUnknown
	}
	lines := strings.Split(string(raw), "\n")
	if len(lines) > 128 {
		return v, ErrUnknown
	}
	for n, line := range lines {
		if len(line) > 1024 {
			return v, ErrUnknown
		}
		lines[n] = strings.TrimSuffix(line, "\r") // Only complete CRLF passed validation.
	}
	fields := map[string]*string{
		"manufacturer": &v.Manufacturer, "model": &v.Model, "device": &v.Device,
		"release": &v.Release, "sandbox": &v.Sandbox, "title": &v.Title, "arch": &v.Arch,
		"ndm.exact": &v.NDMExact, "ndw4.version": &v.NDW4Version,
	}
	seen := map[string]bool{}
	scope, continuation := "", false
	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			continuation = false
			continue
		}
		if strings.HasPrefix(line, strings.Repeat(" ", 23)) {
			if !continuation || len(line) == 23 || line[23] == ' ' || len(line)-23 > 128 {
				return buildTuple{}, ErrUnknown
			}
			continue // Only ignored ndw list wrapping; never a required value.
		}
		continuation = false
		column := strings.IndexByte(line, ':')
		if column != 17 && column != 21 {
			return buildTuple{}, ErrUnknown
		}
		key := strings.TrimLeft(line[:column], " ")
		if !versionKey(key) {
			return buildTuple{}, ErrUnknown
		}
		tail := line[column+1:]
		if tail != "" && tail[0] != ' ' {
			return buildTuple{}, ErrUnknown
		}
		value := strings.TrimSpace(tail)
		if len(value) > 128 {
			return buildTuple{}, ErrUnknown
		}
		path := key
		if column == 17 {
			scope = ""
			if versionSection(key) {
				if value != "" || seen[key] {
					return buildTuple{}, ErrUnknown
				}
				seen[key], scope = true, key
				continue
			}
		} else {
			if scope == "" || !versionChild(scope, key) {
				return buildTuple{}, ErrUnknown
			}
			path = scope + "." + key
			continuation = path == "ndw.features" || path == "ndw.components"
		}
		if value == "" || seen[path] {
			return buildTuple{}, ErrUnknown
		}
		seen[path] = true
		if field := fields[path]; field != nil {
			*field = value
		}
	}
	for path := range fields {
		if !seen[path] {
			return buildTuple{}, ErrUnknown
		}
	}
	return v, nil
}

func versionKey(key string) bool {
	if key == "" || key[0] < 'a' || key[0] > 'z' {
		return false
	}
	for _, c := range key {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_') {
			return false
		}
	}
	return true
}
func versionSection(key string) bool {
	return key == "ndm" || key == "bsp" || key == "ndw" || key == "ndw3" || key == "ndw4"
}
func versionChild(scope, key string) bool {
	switch scope {
	case "ndm", "bsp":
		return key == "exact" || key == "cdate"
	case "ndw":
		return key == "features" || key == "components"
	case "ndw3", "ndw4":
		return key == "version"
	}
	return false
}
