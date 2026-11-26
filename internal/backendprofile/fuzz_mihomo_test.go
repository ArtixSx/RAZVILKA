package backendprofile

import "testing"

func FuzzMihomoFailsWithoutPanic(f *testing.F) {
	f.Add(vless)
	f.Add("hysteria2://secret@edge.example:443?sni=edge.example")
	f.Add("ss://YWVzLTI1Ni1nY206cGFzcw@edge.example:8388#ss")
	f.Add("trojan://pw@edge.example:443?sni=edge.example")
	f.Fuzz(func(t *testing.T, raw string) {
		_, _ = Mihomo(raw, MihomoOptions{SOCKSPort: 18090})
	})
}
