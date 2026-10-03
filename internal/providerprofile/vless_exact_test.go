package providerprofile

import (
	"strings"
	"testing"
)

func TestCanonicalVLESSRejectsLossyFieldsBeforeNormalization(t *testing.T) {
	const base = `"type":"vless","server":"edge.example","server_port":443,"uuid":"` + xrayUUID + `"`
	for _, fields := range []string{
		`"tls":{"enabled":true,"certificate_path":"/private.pem"}`,
		`"tls":{"enabled":true,"certificate_public_key_sha256":["pin"]}`,
		`"tls":{"enabled":true,"alpn":["h2",true]}`,
		`"tls":{"enabled":true,"utls":{"enabled":"true","fingerprint":"chrome"}}`,
		`"tls":{"enabled":true,"reality":{"enabled":true,"public_key":"KEY","spider_x":"/path"}}`,
		`"detour":"other"`, `"bind_interface":"wan2"`, `"unknown_secret":"canary"`,
	} {
		raw := `{` + base + `,` + fields + `}`
		if _, err := VLESSProfileFromJSON([]byte(raw)); err == nil {
			t.Fatalf("canonical projection accepted unmapped settings: %s", fields)
		}
		if result, err := ParseXrayProfile(`{"outbounds":[`+raw+`]}`, 0); err == nil || len(result.Config) != 0 {
			t.Fatalf("normalization erased unmapped settings: %s", fields)
		}
	}
}

func TestCanonicalVLESSRejectsDuplicateAndTrailingJSON(t *testing.T) {
	const raw = `{"type":"vless","server":"edge.example","server_port":443,"uuid":"` + xrayUUID + `","tls":{"enabled":true}}`
	for _, input := range []string{raw + `{}`, strings.Replace(raw, `"enabled":true`, `"enabled":false,"enabled":true`, 1), strings.Replace(raw, `443`, `443.1`, 1)} {
		if _, err := VLESSProfileFromJSON([]byte(input)); err == nil {
			t.Fatal("ambiguous canonical profile accepted")
		}
	}
	p, err := VLESSProfileFromJSON([]byte(raw))
	if err != nil || p.ServerName != "edge.example" {
		t.Fatalf("hostname TLS default lost: %+v %v", p, err)
	}
}

func TestXrayRAWCanonicalAliasAndNoLossyTCPOptions(t *testing.T) {
	for _, alias := range []string{"raw", "tcp"} {
		result, err := ParseXrayProfile(testVLESS+"security=tls&type="+alias, 0)
		if err != nil || !strings.Contains(string(result.Config), `"network": "tcp"`) {
			t.Fatalf("RAW alias failed: %v", err)
		}
		for _, field := range []string{"path=%2Ftunnel", "host=front.example", "serviceName=gate"} {
			if _, err := ParseXrayProfile(testVLESS+"security=tls&type="+alias+"&"+field, 0); err == nil {
				t.Fatal("TCP ignored a required transport option")
			}
		}
	}
	for _, transport := range []string{"xhttp", "splithttp"} {
		if result, err := ParseXrayProfile(testVLESS+"security=tls&type="+transport, 0); err == nil || len(result.Config) != 0 {
			t.Fatal("XHTTP must remain unavailable until its own compiler and native checks exist")
		}
	}
}

func TestXrayRejectsNativeMultiplexWithoutMapping(t *testing.T) {
	raw := `{"outbounds":[{"type":"vless","server":"edge.example","server_port":443,"uuid":"` + xrayUUID + `","tls":{"enabled":true},"multiplex":{"enabled":true,"protocol":"smux"}}]}`
	if _, err := ParseXrayProfile(raw, 0); ErrorCode(err) != "XRAY_UNSUPPORTED_PROFILE" {
		t.Fatalf("multiplex lost during Xray projection: %v", err)
	}
}
