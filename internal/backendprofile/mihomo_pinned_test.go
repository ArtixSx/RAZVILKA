package backendprofile

import (
	"net/netip"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestMihomoPinnedProbePreservesOriginalTLSAndTransportIdentity(t *testing.T) {
	for _, raw := range []string{
		"vless://123e4567-e89b-12d3-a456-426614174000@edge.example:443?security=tls&type=tcp",
		"vless://123e4567-e89b-12d3-a456-426614174000@edge.example:443?security=tls&sni=cover.example&type=ws&host=ws.example&path=%2Frequired",
		"hy2://testpass@edge.example:443",
		"tuic://123e4567-e89b-12d3-a456-426614174000:testpass@edge.example:443?congestion_control=bbr",
	} {
		options := MihomoOptions{SOCKSPort: 18090}
		base, err := Mihomo(raw, options)
		if err != nil {
			t.Fatal(err)
		}
		pinned, err := MihomoPinnedForProbe(raw, options, "edge.example", netip.MustParseAddr("1.1.1.2"))
		if err != nil || pinned.NativeValidated || pinned.ServiceVerified || pinned.LiveApplied {
			t.Fatal(err)
		}
		var before, after map[string]any
		if yaml.Unmarshal([]byte(base.Config), &before) != nil || yaml.Unmarshal([]byte(pinned.Config), &after) != nil {
			t.Fatal("config decode")
		}
		node := after["proxies"].([]any)[0].(map[string]any)
		if node["server"] != "edge.example" || after["hosts"].(map[string]any)["edge.example"] != "1.1.1.2" {
			t.Fatal("pin or original endpoint identity lost")
		}
		// Undo only the admitted exact host pin, then compare the whole
		// generated document: no transport, key, rule or scope can disappear.
		delete(after, "hosts")
		b, _ := yaml.Marshal(before)
		a, _ := yaml.Marshal(after)
		if string(a) != string(b) {
			t.Fatal("pinning changed unrelated semantics")
		}
	}
}

func TestMihomoPinnedProbeRejectsDifferentEndpointAndPrivateAddresses(t *testing.T) {
	for _, address := range []string{"127.0.0.1", "192.168.1.1", "169.254.169.254", "0.0.0.0", "::1", "2606:4700:4700::1111"} {
		if _, err := MihomoPinnedForProbe(vless, MihomoOptions{SOCKSPort: 18090}, "edge.example", netip.MustParseAddr(address)); err == nil {
			t.Fatal(address)
		}
	}
	if _, err := MihomoPinnedForProbe(vless, MihomoOptions{SOCKSPort: 18090}, "different.example", netip.MustParseAddr("1.1.1.2")); err == nil {
		t.Fatal("changed endpoint accepted")
	}
	if _, err := MihomoPinnedForProbe("vless://123e4567-e89b-12d3-a456-426614174000@1.1.1.3:443?security=tls&sni=edge.example", MihomoOptions{SOCKSPort: 18090}, "1.1.1.3", netip.MustParseAddr("1.1.1.2")); err == nil {
		t.Fatal("literal endpoint changed")
	}
}
