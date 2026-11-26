package providerprofile

import (
	"encoding/base64"
	"testing"
)

func FuzzParseProfileFailsWithoutPanic(f *testing.F) {
	uri := "vless://123e4567-e89b-12d3-a456-426614174000@edge.example:443?security=tls&sni=edge.example&type=tcp#node"
	for _, seed := range []string{
		uri,
		uri + "\n" + uri,
		base64.StdEncoding.EncodeToString([]byte(uri + "\n")),
		"proxies:\n  - name: a\n    type: vless\n    server: edge.example\n    port: 443\n    uuid: 123e4567-e89b-12d3-a456-426614174000\n",
		`{"outbounds":[{"type":"vless","server":"edge.example","server_port":443}]}`,
		"hysteria2://secret@edge.example:443?sni=edge.example",
		"ss://YWVzLTI1Ni1nY206cGFzcw@edge.example:8388#ss",
		"",
	} {
		f.Add(seed, 0)
	}
	f.Fuzz(func(t *testing.T, raw string, selected int) {
		if len(raw) > 64<<10 {
			return
		}
		_, _ = ParseProfile(raw)
		_, _ = ParseProfileWithSelection(raw, selected)
		_, _ = ParseURI(raw)
	})
}
