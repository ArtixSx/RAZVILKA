package providerprofile

import (
	"encoding/json"
	"strings"
	"testing"
)

func firstImportedOutbound(t *testing.T, config []byte) map[string]any {
	t.Helper()
	var doc map[string]any
	if err := json.Unmarshal(config, &doc); err != nil {
		t.Fatal(err)
	}
	return doc["outbounds"].([]any)[0].(map[string]any)
}

func TestAuditHysteriaAuthenticationAndObfuscationSurviveImport(t *testing.T) {
	for _, auth := range []string{"alice:canary-password", "alice%3Acanary-password"} {
		result, err := ParseURI("hy2://" + auth + "@edge.example:443/?obfs=salamander&obfs-password=canary-obfs#canary-obfs")
		if err != nil {
			t.Fatal(err)
		}
		out := firstImportedOutbound(t, result.Config)
		if out["password"] != "alice:canary-password" {
			t.Error("Hysteria userpass authentication changed during import")
		}
		obfs, _ := out["obfs"].(map[string]any)
		if obfs["type"] != "salamander" || obfs["password"] != "canary-obfs" {
			t.Error("Hysteria obfuscation settings lost during import")
		}
		preview, _ := json.Marshal(result.Preview)
		if strings.Contains(string(preview), "canary-") {
			t.Error("Hysteria preview exposed authentication or obfuscation secret")
		}
	}
}

func TestAuditQUICProfilesRejectUnsafeOrAmbiguousURIOptions(t *testing.T) {
	for _, base := range []string{"hy2://secret@edge.example:443/?", "tuic://123e4567-e89b-12d3-a456-426614174000:secret@edge.example:443/?"} {
		for _, query := range []string{"insecure=1", "allowInsecure=true", "insecure=true&insecure=false", "sni=one.example&serverName=two.example", "sni=%zz", "sni=one;insecure=1", "pinSHA256=canary-pin", "unknown=canary-value"} {
			result, err := ParseProfile(base + query)
			if err == nil || len(result.Config) != 0 {
				t.Errorf("unsafe or ignored URI options accepted: %s", query)
			}
		}
	}
}

func TestAuditAllNativeAndClashProtocolsRejectInsecureTLS(t *testing.T) {
	for _, protocol := range []string{"hysteria2", "tuic", "shadowsocks"} {
		for _, value := range []string{"true", `"true"`} {
			raw := `{"outbounds":[{"type":"` + protocol + `","server":"edge.example","server_port":443,"uuid":"123e4567-e89b-12d3-a456-426614174000","password":"secret","method":"aes-256-gcm","tls":{"enabled":true,"insecure":` + value + `}}]}`
			result, err := ParseProfile(raw)
			if err == nil || len(result.Config) != 0 {
				t.Errorf("native insecure TLS accepted for %s", protocol)
			}
			raw = "proxies:\n  - type: " + protocol + "\n    server: edge.example\n    port: 443\n    uuid: 123e4567-e89b-12d3-a456-426614174000\n    password: secret\n    cipher: aes-256-gcm\n    tls: true\n    skip-cert-verify: " + value + "\n"
			result, err = ParseProfile(raw)
			if err == nil || len(result.Config) != 0 {
				t.Errorf("Clash insecure TLS accepted for %s", protocol)
			}
		}
	}
}

func TestAuditVLESSHTTPHostSurvivesImport(t *testing.T) {
	result, err := ParseURI(testVLESS + "security=tls&type=h2&host=front.example,other.example&path=%2Ftunnel")
	if err != nil {
		t.Fatal(err)
	}
	transport := firstImportedOutbound(t, result.Config)["transport"].(map[string]any)
	hosts, _ := transport["host"].([]any)
	if len(hosts) != 2 || hosts[0] != "front.example" || hosts[1] != "other.example" || transport["path"] != "/tunnel" {
		t.Fatal("HTTP transport host/path changed during import")
	}
}

func TestAuditClashH2HostAndPathSurviveImport(t *testing.T) {
	raw := "proxies:\n  - type: vless\n    server: edge.example\n    port: 443\n    uuid: 123e4567-e89b-12d3-a456-426614174000\n    tls: true\n    network: h2\n    h2-opts:\n      host: [front.example, other.example]\n      path: /tunnel\n"
	result, err := ParseProfile(raw)
	if err != nil {
		t.Fatal(err)
	}
	transport := firstImportedOutbound(t, result.Config)["transport"].(map[string]any)
	hosts, _ := transport["host"].([]any)
	if len(hosts) != 2 || hosts[0] != "front.example" || hosts[1] != "other.example" || transport["path"] != "/tunnel" {
		t.Fatal("Clash H2 transport host/path changed during import")
	}
}

func TestAuditShadowsocksCannotDropMalformedPluginOptions(t *testing.T) {
	for _, query := range []string{"plugin=%zz", "plugin=&plugin=obfs-local", "plugin=;ignored=1", "unknown=secret"} {
		if _, err := ParseURI("ss://YWVzLTI1Ni1nY206c2VjcmV0@edge.example:8388/?" + query); err == nil {
			t.Errorf("Shadowsocks accepted malformed or unsupported query: %s", query)
		}
	}
}

func TestAuditClashHTTPOptionsAndUnsupportedShapes(t *testing.T) {
	const base = "proxies:\n  - type: vless\n    server: edge.example\n    port: 443\n    uuid: 123e4567-e89b-12d3-a456-426614174000\n    network: http\n    http-opts:\n"
	result, err := ParseProfile(base + "      method: GET\n      path: [/tunnel]\n      headers:\n        Host: [front.example]\n        X-Test: [one, two]\n")
	if err != nil {
		t.Fatal(err)
	}
	transport := firstImportedOutbound(t, result.Config)["transport"].(map[string]any)
	hosts, _ := transport["host"].([]any)
	headers, _ := transport["headers"].(map[string]any)
	values, _ := headers["X-Test"].([]any)
	if transport["method"] != "GET" || transport["path"] != "/tunnel" || len(hosts) != 1 || hosts[0] != "front.example" || len(values) != 2 {
		t.Fatal("Clash HTTP options were lost")
	}
	for _, opts := range []string{"      path: [/one, /two]\n", "      path: /tunnel\n", "      method: 23\n", "      headers: invalid\n", "      headers:\n        Host: [true]\n"} {
		if _, err := ParseProfile(base + opts); err == nil {
			t.Error("unsupported HTTP options were silently accepted")
		}
	}
}

func TestAuditQUICOptionsPreserveSecureAcceptedValues(t *testing.T) {
	result, err := ParseURI("hy2://auth@edge.example:443/?allowInsecure=false&serverName=front.example&alpn=h3&obfs=salamander&obfs-password=%20secret%20")
	if err != nil {
		t.Fatal(err)
	}
	out := firstImportedOutbound(t, result.Config)
	if out["obfs"].(map[string]any)["password"] != " secret " {
		t.Fatal("obfuscation password whitespace changed")
	}
	tls := out["tls"].(map[string]any)
	if tls["server_name"] != "front.example" || tls["insecure"] == true {
		t.Fatal("secure TLS parameters changed")
	}
	for _, query := range []string{"obfs=salamander", "obfs-password=secret", "obfs=unknown&obfs-password=secret", "insecure=invalid", "sni=front%00example"} {
		if _, err := ParseURI("hy2://auth@edge.example:443/?" + query); err == nil {
			t.Errorf("invalid HY2 options accepted: %s", query)
		}
	}
}
