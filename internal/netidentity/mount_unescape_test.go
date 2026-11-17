package netidentity

import (
	"strings"
	"testing"
)

// Exact previous byte builder, test-only for paired/differential evidence.
func mountUnescapeBefore(s string) (string, bool) {
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

func TestMountUnescapePreservesExactByteSemantics(t *testing.T) {
	for _, pair := range [][2]string{
		{"", ""}, {"/proc/37/fdinfo", "/proc/37/fdinfo"}, {"a\x00b\xff\xfe", "a\x00b\xff\xfe"},
		{"/каталог", "/каталог"}, {`a\040b\011c\012d\134e`, "a b\tc\nd\\e"},
		{`\134040`, `\040`}, {"\xff\\040\x00", "\xff \x00"},
	} {
		got, ok := mountUnescape(pair[0])
		if !ok || got != pair[1] {
			t.Fatalf("byte decode changed: input=%q output=%q accepted=%t", pair[0], got, ok)
		}
	}
	for _, value := range []string{`\`, `\0`, `\00`, `\000`, `\377`, `\40`, `\x20`, `\\`, `good\040bad\999`} {
		if got, ok := mountUnescape(value); ok || got != "" {
			t.Fatalf("malformed escape accepted: %q", value)
		}
	}
	// The old decoder validates escapes, not Unicode or NUL. Every raw byte
	// except the escape introducer must remain unchanged, including invalid UTF8.
	raw := make([]byte, 0, 255)
	for value := 0; value < 256; value++ {
		if value != '\\' {
			raw = append(raw, byte(value))
		}
	}
	for _, value := range []string{string(raw), strings.Repeat("p", 65536), string(raw) + `\040`, `\011` + string(raw), string(raw) + `\000`} {
		before, beforeOK := mountUnescapeBefore(value)
		after, afterOK := mountUnescape(value)
		if before != after || beforeOK != afterOK {
			t.Fatalf("previous decoder differs for %d raw bytes", len(value))
		}
	}
}

func FuzzMountUnescapeMatchesPreviousByteDecoder(f *testing.F) {
	for _, seed := range []string{"", "/proc", "\x00\xff", `x\040y`, `\134040`, `\000`, `\`, strings.Repeat("p", 4096)} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, value string) {
		if len(value) > 65536 {
			t.Skip("existing mountinfo line bound")
		}
		before, beforeOK := mountUnescapeBefore(value)
		after, afterOK := mountUnescape(value)
		if before != after || beforeOK != afterOK {
			t.Fatal("exact byte decoder parity lost")
		}
	})
}
