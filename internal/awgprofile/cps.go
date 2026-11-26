package awgprofile

import (
	"encoding/hex"
	"errors"
	"strings"
)

// This is a deliberately bounded CPS grammar, not an evaluator. The size limit
// is RAZVILKA's router budget, not a claim about the full upstream grammar.
func validateCPS(s string) error {
	emitted, tokens, timestamps := 0, 0, 0
	for strings.TrimSpace(s) != "" {
		s = strings.TrimSpace(s)
		if !strings.HasPrefix(s, "<") {
			return errors.New("token")
		}
		end := strings.IndexByte(s, '>')
		if end < 0 {
			return errors.New("unterminated")
		}
		body := strings.Fields(s[1:end])
		s = s[end+1:]
		tokens++
		if len(body) == 0 || tokens > 64 {
			return errors.New("count")
		}
		switch body[0] {
		case "t":
			if len(body) != 1 || timestamps > 0 {
				return errors.New("timestamp")
			}
			timestamps++
			emitted += 4
		case "b":
			if len(body) != 2 || !strings.HasPrefix(body[1], "0x") {
				return errors.New("bytes")
			}
			data, e := hex.DecodeString(body[1][2:])
			if e != nil || len(data) == 0 {
				return errors.New("hex")
			}
			emitted += len(data)
		case "r", "rc", "rd":
			if len(body) != 2 {
				return errors.New("length")
			}
			n, e := number(body[1], 1000)
			if e != nil || n == 0 {
				return errors.New("length")
			}
			emitted += int(n)
		default:
			return errors.New("unsupported")
		}
		if emitted > 4096 {
			return errors.New("budget")
		}
	}
	if tokens == 0 {
		return errors.New("empty")
	}
	return nil
}
