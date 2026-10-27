package providerprofile

import (
	"crypto/sha1"
	"encoding/hex"
	"strings"
	"unicode/utf8"
)

// Xray v26.3.27 common/uuid.ParseString maps a 1..30 byte custom VLESS ID
// to UUIDv5 with the nil namespace. Normalize at import so both engines use
// identical authentication bytes. Never trim or Unicode-normalize a custom ID.
func normalizeVLESSID(value string) (string, bool) {
	if looksLikeUUID(value) {
		return value, true
	}
	if len(value) == 0 || len(value) > 30 || !utf8.ValidString(value) || strings.IndexFunc(value, func(r rune) bool { return r < 32 || r == 127 }) >= 0 {
		return "", false
	}
	h := sha1.New()
	_, _ = h.Write(make([]byte, 16))
	_, _ = h.Write([]byte(value))
	b := h.Sum(nil)[:16]
	b[6] = (b[6] & 0x0f) | 0x50
	b[8] = (b[8] & 0x3f) | 0x80
	hexID := hex.EncodeToString(b)
	return hexID[:8] + "-" + hexID[8:12] + "-" + hexID[12:16] + "-" + hexID[16:20] + "-" + hexID[20:], true
}
