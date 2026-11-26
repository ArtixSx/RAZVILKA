package providerprofile

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"
)

const clashTLSProfile = "proxies:\n  - {name: sample, type: vless, server: edge.example, port: 443, uuid: 123e4567-e89b-12d3-a456-426614174000, tls: true, alpn: "

func TestClashVLESSRoundTripPreservesALPN(t *testing.T) {
	want := []string{"h2", strings.Repeat("a", 255), " padded ", "http/1.1"}
	encoded, err := json.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	input := clashTLSProfile + string(encoded) + "}\n"
	imported, err := ParseCanonicalProfile(input)
	if err != nil {
		t.Fatal(err)
	}
	// Reopen the canonical export, as a saved node is reopened for an engine.
	xray, err := ParseXrayProfile(string(imported.Config), 0)
	if err != nil {
		t.Fatal(err)
	}
	out := firstImportedOutbound(t, xray.Config)
	got, err := strictStringList(out["streamSettings"].(map[string]any)["tlsSettings"].(map[string]any)["alpn"])
	if err != nil || !slices.Equal(want, got) {
		t.Fatal("TLS ALPN bytes or preference order changed on export")
	}
	if !strings.Contains(strings.Join(xray.Preview.Warnings, " "), "ALPN") {
		t.Fatal("preview omitted the Xray fingerprint's effect on ALPN")
	}
}

func TestClashVLESSRejectsUnrepresentableALPN(t *testing.T) {
	longName := `"` + strings.Repeat("a", 255) + `"`
	for label, input := range map[string]string{
		"nonstring":          clashTLSProfile + `["h2", 42]}`,
		"invalid UTF-8":      clashTLSProfile + `[!!binary '/w==']}`,
		"empty name":         clashTLSProfile + `[""]}`,
		"256 bytes":          clashTLSProfile + `["` + strings.Repeat("é", 128) + `"]}`,
		"extension too long": clashTLSProfile + "[" + strings.Repeat(longName+", ", 255) + longName + "]}",
		"TLS disabled":       strings.Replace(clashTLSProfile, "tls: true", "tls: false", 1) + `["h2"]}`,
	} {
		t.Run(label, func(t *testing.T) {
			if result, err := ParseCanonicalProfile(input); err == nil || len(result.Config) != 0 {
				t.Fatal("unrepresentable ALPN produced a canonical profile")
			}
		})
	}
}
