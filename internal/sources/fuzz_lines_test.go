package sources

import "testing"

func FuzzValidateLinesFailsWithoutPanic(f *testing.F) {
	for _, seed := range []string{"example.com\n# c\n*.example.org\n", "10.0.0.0/8\n2001:db8::/32\n192.0.2.1\n", "xn--80ak6aa92e.com\n", ""} {
		f.Add("domain", seed)
		f.Add("cidr", seed)
	}
	f.Fuzz(func(t *testing.T, kind, body string) {
		lines, err := validateLinesLimited(kind, body, 64)
		if err != nil {
			return
		}
		// Accepted output is already normalized: validating it again must be stable.
		again, err := validateLinesLimited(kind, joinLines(lines), 64)
		if err != nil || len(again) != len(lines) {
			t.Fatalf("normalized %q is not stable: %q, %v", lines, again, err)
		}
		for i := range lines {
			if again[i] != lines[i] {
				t.Fatalf("normalized %q changed to %q", lines[i], again[i])
			}
		}
	})
}

func joinLines(lines []string) string {
	out := ""
	for _, line := range lines {
		out += line + "\n"
	}
	return out
}
