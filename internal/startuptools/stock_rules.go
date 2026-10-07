package startuptools

import (
	"bytes"
	"strconv"
	"strings"
)

// Only the pinned 4.4.0 deployment with held absence of all name inputs may
// use this adapter. It never guesses a name, drops a row or changes another
// field whose value happens to be a built-in table name.
func stockNumericRules(data []byte) ([]byte, error) {
	if len(data) > maxOutputBytes || bytes.IndexByte(data, 0) >= 0 || len(data) != 0 && data[len(data)-1] != '\n' {
		return nil, at("STOCK_RULE_FRAMING", nil)
	}
	var result strings.Builder
	rows, tokens := 0, 0
	for _, line := range strings.Split(string(data), "\n") {
		if line == "" {
			continue
		}
		rows++
		if rows > 8192 || len(line) > 4096 || strings.ContainsRune(line, '\r') {
			return nil, at("STOCK_RULE_BOUNDS", nil)
		}
		fields := strings.Fields(line)
		tokens += len(fields)
		if len(fields) < 3 || len(fields) > 64 || tokens > 65536 || !strings.HasSuffix(fields[0], ":") {
			return nil, at("STOCK_RULE_SYNTAX", nil)
		}
		if _, ok := stockDecimal(strings.TrimSuffix(fields[0], ":"), 32); !ok {
			return nil, at("STOCK_RULE_PRIORITY", nil)
		}
		for i := 1; i < len(fields); i++ {
			kind := fields[i]
			switch kind {
			case "not", "nop", "blackhole", "unreachable", "prohibit":
				continue
			case "from", "to", "fwmark", "iif", "oif", "goto", "lookup", "table", "tos", "dsfield", "suppress_prefixlength", "suppress_ifgroup", "realms":
			default:
				return nil, at("STOCK_RULE_UNKNOWN_FIELD", nil)
			}
			i++
			if i >= len(fields) {
				return nil, at("STOCK_RULE_SYNTAX", nil)
			}
			value := fields[i]
			switch kind {
			case "lookup", "table":
				switch value {
				case "local":
					value = "255"
				case "main":
					value = "254"
				case "default":
					value = "253"
				}
				if n, ok := stockDecimal(value, 32); !ok || n == 0 {
					return nil, at("STOCK_RULE_TABLE", nil)
				}
			case "suppress_ifgroup":
				if value == "default" {
					value = "0"
				}
				if _, ok := stockDecimal(value, 31); !ok {
					return nil, at("STOCK_RULE_GROUP", nil)
				}
			case "tos", "dsfield":
				if len(value) != 4 || !strings.HasPrefix(value, "0x") {
					return nil, at("STOCK_RULE_DSFIELD", nil)
				}
				if n, err := strconv.ParseUint(value[2:], 16, 8); err != nil || n == 0 || value != "0x"+stockHexByte(byte(n)) {
					return nil, at("STOCK_RULE_DSFIELD", err)
				}
			case "realms":
				parts := strings.Split(value, "/")
				if len(parts) > 2 {
					return nil, at("STOCK_RULE_REALM", nil)
				}
				for j, part := range parts {
					if part == "unknown" {
						part = "0"
					}
					if _, ok := stockDecimal(part, 16); !ok {
						return nil, at("STOCK_RULE_REALM", nil)
					}
					parts[j] = part
				}
				value = strings.Join(parts, "/")
			}
			fields[i] = value
		}
		result.WriteString(strings.Join(fields, " "))
		result.WriteByte('\n')
		if result.Len() > maxOutputBytes {
			return nil, at("STOCK_RULE_BOUNDS", nil)
		}
	}
	return []byte(result.String()), nil
}

func stockDecimal(value string, bits int) (uint64, bool) {
	n, err := strconv.ParseUint(value, 10, bits)
	return n, err == nil && strconv.FormatUint(n, 10) == value
}

func stockHexByte(value byte) string {
	const digits = "0123456789abcdef"
	return string([]byte{digits[value>>4], digits[value&15]})
}
