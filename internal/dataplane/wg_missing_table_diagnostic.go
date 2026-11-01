package dataplane

import (
	"fmt"
	"strings"
)

// This is format negotiation, not absence evidence. A failed iproute2 JSON
// dump can flush its opening '[' only after the exact ENOENT diagnostic; the
// native IPv4/IPv6 fixture observes this on a genuinely unused table. Every
// caller must independently confirm the complete table through the same
// original command owner. A successful malformed JSON dump never enters here.
func wgMissingTableDiagnostic(data []byte, family int, jsonOutput bool) bool {
	if len(data) > 256 || family != 4 && family != 6 {
		return false
	}
	message := strings.TrimSpace(string(data))
	absent := fmt.Sprintf("Error: ipv%d: FIB table does not exist.", family)
	exact := func(s string) bool { return s == absent || s == absent+"\nDump terminated" }
	if exact(message) {
		return true
	}
	if !jsonOutput {
		return false
	}
	// At most one empty framing fragment. No route bytes, duplicate arrays,
	// additional diagnostics or wrong-family errors can negotiate a retry.
	if strings.HasPrefix(message, "[]") && exact(strings.TrimSpace(message[2:])) {
		return true
	}
	if strings.HasSuffix(message, "[]") && exact(strings.TrimSpace(message[:len(message)-2])) {
		return true
	}
	if strings.HasPrefix(message, "[") && strings.HasSuffix(message, "]") && exact(strings.TrimSpace(message[1:len(message)-1])) {
		return true
	}
	return strings.HasSuffix(message, "\n[") && exact(strings.TrimSpace(strings.TrimSuffix(message, "\n[")))
}
