package providerprofile

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestParseVLESSRealityDoesNotExposeSecretsInPreview(t *testing.T) {
	const uuid = "123e4567-e89b-12d3-a456-426614174000"
	result, err := ParseURI("vless://" + uuid + "@edge.example:443?security=reality&sni=front.example&fp=chrome&pbk=PUBLIC_KEY&sid=abcd&type=grpc&serviceName=gate#Home")
	if err != nil {
		t.Fatal(err)
	}
	if result.Preview.Protocol != "VLESS" || result.Preview.Server != "edge.example" || result.Preview.Transport != "grpc" || !result.Preview.TLS {
		t.Fatalf("unexpected preview: %+v", result.Preview)
	}
	preview, _ := json.Marshal(result.Preview)
	if strings.Contains(string(preview), uuid) || strings.Contains(string(preview), "PUBLIC_KEY") {
		t.Fatalf("preview leaked a credential: %s", preview)
	}
	if !strings.Contains(string(result.Config), uuid) || !strings.Contains(string(result.Config), "PUBLIC_KEY") {
		t.Fatal("generated config lost VLESS credentials")
	}
}

func TestParseHysteriaTUICAndShadowsocks(t *testing.T) {
	tests := []struct {
		uri      string
		protocol string
	}{
		{"hysteria2://secret@example.com:8443?sni=front.example#HY2", "Hysteria2"},
		{"tuic://123e4567-e89b-12d3-a456-426614174000:secret@example.com:443?sni=front.example", "TUIC"},
		{"ss://YWVzLTI1Ni1nY206c2VjcmV0@example.com:8388#SS", "Shadowsocks"},
	}
	for _, test := range tests {
		t.Run(test.protocol, func(t *testing.T) {
			result, err := ParseURI(test.uri)
			if err != nil {
				t.Fatal(err)
			}
			if result.Preview.Protocol != test.protocol || result.Preview.Server != "example.com" {
				t.Fatalf("unexpected preview: %+v", result.Preview)
			}
			if !json.Valid(result.Config) {
				t.Fatalf("invalid generated JSON: %s", result.Config)
			}
		})
	}
}

func TestParseURIRejectsMissingSecretsAndUnsupportedSchemes(t *testing.T) {
	for _, value := range []string{"", "https://example.com", "vless://bad@example.com:443", "hysteria2://example.com:443", "tuic://user@example.com:443"} {
		if _, err := ParseURI(value); err == nil {
			t.Fatalf("accepted invalid profile %q", value)
		}
	}
}
