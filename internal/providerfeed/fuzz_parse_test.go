package providerfeed

import (
	"context"
	"testing"
)

func FuzzParseFeedWindowFailsWithoutPanic(f *testing.F) {
	uri := "vless://123e4567-e89b-12d3-a456-426614174000@edge.example:443?security=tls&sni=edge.example&type=tcp#node"
	for _, seed := range []string{uri, uri + "\n" + uri + "\n", `{"keys":[{"key":"` + uri + `"}]}`, `[{"uri":"` + uri + `"}]`, "# comment\n\n"} {
		for _, format := range []string{"uri-lines", "keys-json", "profile"} {
			f.Add([]byte(seed), format, 4, 0)
		}
	}
	f.Fuzz(func(t *testing.T, data []byte, format string, limit, cursor int) {
		_, _ = parseWindow(context.Background(), data, format, limit, cursor)
	})
}
