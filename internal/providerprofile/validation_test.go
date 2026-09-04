package providerprofile

import (
	"encoding/base64"
	"encoding/json"
	"net/url"
	"strings"
	"testing"
)

const testVLESS = "vless://123e4567-e89b-12d3-a456-426614174000@edge.example:443?"

func TestVLESSRejectsUnsupportedAndAmbiguousParameters(t *testing.T) {
	for _, tc := range []struct{ query, code string }{
		{"type=xhttp", "UNSUPPORTED_TRANSPORT"},
		{"type=splithttp", "UNSUPPORTED_TRANSPORT"},
		{"type=secret-canary", "UNSUPPORTED_TRANSPORT"},
		{"security=secret-canary", "UNSUPPORTED_SECURITY"},
		{"flow=secret-canary", "UNSUPPORTED_FLOW"},
		{"flow=xtls-rprx-vision&security=tls&type=ws", "UNSUPPORTED_FLOW"},
		{"flow=xtls-rprx-vision&security=none", "UNSUPPORTED_FLOW"},
		{"packetEncoding=secret-canary", "UNSUPPORTED_PACKET_ENCODING"},
		{"security=tls&allowInsecure=1", "INSECURE_TLS"},
		{"type=xhttp&type=tcp", "INVALID_PARAMETERS"},
		{"sni=one&serverName=two", "INVALID_PARAMETERS"},
		{"type=%ff", "INVALID_PARAMETERS"},
		{"type=tcp%00", "INVALID_PARAMETERS"},
		{"type=%zz", "INVALID_PARAMETERS"},
		{"type=tcp;security=reality", "INVALID_PARAMETERS"},
		{"encryption=secret-canary", "INVALID_PARAMETERS"},
		{"headerType=http", "INVALID_PARAMETERS"},
		{"unknown=secret-canary", "INVALID_PARAMETERS"},
	} {
		t.Run(tc.query, func(t *testing.T) {
			raw := testVLESS + tc.query
			for _, input := range []string{raw, base64.StdEncoding.EncodeToString([]byte(raw))} {
				result, err := ParseProfile(input)
				if err == nil || ErrorCode(err) != tc.code || len(result.Config) != 0 {
					t.Fatalf("wrong rejection code: %v", err)
				}
				if strings.Contains(err.Error(), "secret-canary") || strings.Contains(err.Error(), "123e4567") {
					t.Fatal("error leaked credentials")
				}
			}
		})
	}
}

func TestVLESSSupportedModesAndIPv6(t *testing.T) {
	for _, transport := range []string{"tcp", "ws", "websocket", "grpc", "http", "h2"} {
		result, err := ParseURI(testVLESS + "security=tls&type=" + transport + "&packetEncoding=xudp")
		if err != nil {
			t.Fatal(err)
		}
		var doc map[string]any
		json.Unmarshal(result.Config, &doc)
		out := doc["outbounds"].([]any)[0].(map[string]any)
		if out["packet_encoding"] != "xudp" {
			t.Fatal("lost packet encoding")
		}
		if transport != "tcp" && out["transport"] == nil {
			t.Fatal("silent TCP fallback")
		}
	}
	_, err := ParseURI("vless://123e4567-e89b-12d3-a456-426614174000@[2001:db8::1]:443?security=tls&flow=xtls-rprx-vision&type=tcp")
	if err != nil {
		t.Fatal(err)
	}
}

func TestVLESSNativeAndClashCannotBypassPolicy(t *testing.T) {
	const fields = `"type":"vless","server":"edge.example","server_port":443,"uuid":"123e4567-e89b-12d3-a456-426614174000"`
	for _, extra := range []string{
		`"transport":{"type":"xhttp"}`, `"transport":{"type":"xhttp","type":"ws"}`,
		`"transport":"xhttp"`, `"flow":123`, `"flow":"secret-canary"`,
		`"packet_encoding":"unknown"`, `"tls":{"enabled":true,"insecure":true}`,
		`"tls":{"enabled":"true"}`, `"tls":{"enabled":true,"insecure":"true"}`,
	} {
		result, err := ParseProfile(`{"outbounds":[{` + fields + `,` + extra + `}]}`)
		if err == nil || len(result.Config) != 0 {
			t.Fatal("native bypass accepted")
		}
	}
	const yamlPrefix = "proxies:\n  - type: vless\n    name: secret-canary\n    server: edge.example\n    port: 443\n    uuid: 123e4567-e89b-12d3-a456-426614174000\n"
	for _, extra := range []string{"network: xhttp", "network: 23", "flow: secret-canary", "packet-encoding: unknown", "skip-cert-verify: true", "tls: invalid"} {
		result, err := ParseProfile(yamlPrefix + "    " + extra + "\n")
		if err == nil || len(result.Config) != 0 {
			t.Fatal("YAML bypass accepted")
		}
		if strings.Contains(err.Error(), "secret-canary") {
			t.Fatal("YAML name leaked into error")
		}
	}
}

func TestVLESSPreviewMasksCredentialInLabel(t *testing.T) {
	for _, label := range []string{"123e4567-e89b-12d3-a456-426614174000", "vless://another-secret@edge.example"} {
		result, err := ParseURI(testVLESS + "security=tls#" + url.PathEscape(label))
		if err != nil {
			t.Fatal(err)
		}
		preview, _ := json.Marshal(result.Preview)
		if strings.Contains(string(preview), "123e4567") || strings.Contains(string(preview), "another-secret") {
			t.Fatal("preview leaked label credential")
		}
	}
}

func FuzzVLESSModesFailClosed(f *testing.F) {
	for _, seed := range []string{"xhttp", "tcp", "ws", "grpc", "secret-canary", "\x00", "%ff"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, mode string) {
		if len(mode) > 1024 {
			return
		}
		result, err := ParseURI(testVLESS + "security=tls&type=" + url.QueryEscape(mode))
		if err != nil {
			if len(result.Config) != 0 {
				t.Fatal("rejected input created config")
			}
			return
		}
		switch strings.ToLower(strings.TrimSpace(mode)) {
		case "", "tcp", "ws", "websocket", "grpc", "http", "h2":
		default:
			t.Fatal("unsupported transport accepted")
		}
	})
}
