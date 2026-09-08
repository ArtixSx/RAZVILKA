package providerprofile

import (
	"encoding/base64"
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

func TestParseURIExplainsWebPageInsteadOfKey(t *testing.T) {
	_, err := ParseURI("https://tiagorrg.github.io/vless-checker/")
	if err == nil || !strings.Contains(err.Error(), "сам ключ") {
		t.Fatalf("unexpected page URL error: %v", err)
	}
}

func TestParseProfileAcceptsTextAndBase64SubscriptionsWithoutPreviewLeaks(t *testing.T) {
	const uuid = "123e4567-e89b-12d3-a456-426614174000"
	subscription := "vless://" + uuid + "@one.example:443?security=tls#One\n" +
		"hysteria2://super-secret@two.example:8443?sni=front.example#Two\n"
	for name, input := range map[string]string{
		"plain":  subscription,
		"base64": base64.StdEncoding.EncodeToString([]byte(subscription)),
	} {
		t.Run(name, func(t *testing.T) {
			result, err := ParseProfile(input)
			if err != nil {
				t.Fatal(err)
			}
			if result.Preview.NodeCount != 2 || len(result.Preview.Nodes) != 2 || result.Preview.EngineID != "sing-box" {
				t.Fatalf("unexpected bundle preview: %+v", result.Preview)
			}
			preview, _ := json.Marshal(result.Preview)
			if strings.Contains(string(preview), uuid) || strings.Contains(string(preview), "super-secret") {
				t.Fatalf("bundle preview leaked a credential: %s", preview)
			}
			if !strings.Contains(string(result.Config), `"type": "selector"`) || !strings.Contains(string(result.Config), `"type": "urltest"`) || !strings.Contains(string(result.Config), `"default": "auto"`) {
				t.Fatalf("multi-node config has no automatic local selector: %s", result.Config)
			}
		})
	}
}

func TestParseProfileAllowsExplicitInitialNodeSelection(t *testing.T) {
	const subscription = "vless://123e4567-e89b-12d3-a456-426614174000@one.example:443?security=tls#One\n" +
		"hysteria2://secret@two.example:8443?sni=front.example#Two\n"
	result, err := ParseProfileWithSelection(subscription, 1)
	if err != nil {
		t.Fatal(err)
	}
	if result.Preview.SelectedIndex != 1 || !strings.Contains(string(result.Config), `"outbounds": [
        "node-02",
        "node-01"`) {
		t.Fatalf("explicit selection was lost: preview=%+v config=%s", result.Preview, result.Config)
	}
	for _, invalid := range []int{-1, 2} {
		if _, err := ParseProfileWithSelection(subscription, invalid); err == nil {
			t.Fatalf("accepted invalid selected index %d", invalid)
		}
	}
}

func TestParseProfileNormalizesSingBoxJSONAndDropsUnmanagedSections(t *testing.T) {
	const source = `{
  "inbounds": [{"type":"mixed","listen":"0.0.0.0","listen_port":1080}],
  "experimental": {"clash_api":{"external_controller":"0.0.0.0:9090"}},
  "outbounds": [
	    {"type":"vless","tag":"Home","server":"edge.example","server_port":443,"uuid":"123e4567-e89b-12d3-a456-426614174000","tls":{"enabled":true,"server_name":"front.example","certificate_path":"/opt/etc/private.pem"}},
    {"type":"direct","tag":"direct"}
  ]
}`
	result, err := ParseProfile(source)
	if err != nil {
		t.Fatal(err)
	}
	if result.Preview.Format != "sing-box-json" || result.Preview.NodeCount != 1 || result.Preview.Nodes[0].Name != "Home" {
		t.Fatalf("unexpected preview: %+v", result.Preview)
	}
	config := string(result.Config)
	if strings.Contains(config, "0.0.0.0") || strings.Contains(config, "experimental") || strings.Contains(config, "clash_api") || strings.Contains(config, "certificate_path") || strings.Contains(config, "private.pem") {
		t.Fatalf("unmanaged source sections survived normalization: %s", config)
	}
	if !strings.Contains(config, `"final": "proxy"`) || !strings.Contains(config, `"tag": "proxy"`) {
		t.Fatalf("normalized config has no deterministic proxy route: %s", config)
	}
}

func TestParseProfileNormalizesClashYAMLAndDropsUnmanagedSections(t *testing.T) {
	const source = `port: 7890
external-controller: 0.0.0.0:9090
secret: panel-secret
dns:
  enable: true
  nameserver: [1.1.1.1]
rules:
  - MATCH,DIRECT
proxies:
  - name: Home Reality
    type: vless
    server: edge.example
    port: 443
    uuid: 123e4567-e89b-12d3-a456-426614174000
    tls: true
    servername: front.example
    client-fingerprint: chrome
    network: grpc
    grpc-opts:
      grpc-service-name: gate
    reality-opts:
      public-key: PUBLIC_KEY
      short-id: abcd
  - name: Fast HY2
    type: hysteria2
    server: hy.example
    port: 8443
    password: super-secret
    sni: cdn.example
  - name: Unsupported Trojan
    type: trojan
    server: ignored.example
    port: 443
    password: ignored-secret
`
	result, err := ParseProfile(source)
	if err != nil {
		t.Fatal(err)
	}
	if result.Preview.Format != "clash-mihomo-yaml" || result.Preview.NodeCount != 2 || len(result.Preview.Warnings) < 2 {
		t.Fatalf("unexpected YAML preview: %+v", result.Preview)
	}
	preview, _ := json.Marshal(result.Preview)
	if strings.Contains(string(preview), "123e4567") || strings.Contains(string(preview), "super-secret") || strings.Contains(string(preview), "PUBLIC_KEY") {
		t.Fatalf("YAML preview leaked credentials: %s", preview)
	}
	config := string(result.Config)
	for _, forbidden := range []string{"external-controller", "panel-secret", "nameserver", "MATCH,DIRECT", "ignored.example", "ignored-secret"} {
		if strings.Contains(config, forbidden) {
			t.Fatalf("unmanaged YAML field %q survived normalization: %s", forbidden, config)
		}
	}
	for _, required := range []string{`"type": "selector"`, `"server": "edge.example"`, `"public_key": "PUBLIC_KEY"`, `"server": "hy.example"`} {
		if !strings.Contains(config, required) {
			t.Fatalf("normalized YAML lost %s: %s", required, config)
		}
	}
}

func TestParseProfileRejectsBrokenSupportedClashProxy(t *testing.T) {
	const source = `proxies:
  - name: Broken
    type: vless
    server: edge.example
    port: 443
    uuid: not-a-uuid
`
	if _, err := ParseProfile(source); err == nil {
		t.Fatal("accepted broken supported Clash proxy")
	}
}

func TestParseProfileRejectsUnsupportedOrOversizedBundles(t *testing.T) {
	invalid := []string{
		`{"outbounds":[{"type":"socks","server":"proxy.example","server_port":1080}]}`,
		`{"outbounds":[{"type":"shadowsocks","server":"proxy.example","server_port":8388,"method":"aes-256-gcm","password":"secret","plugin":"arbitrary-command"}]}`,
		`{"inbounds":[]}`,
		"https://example.com/subscription",
		strings.Repeat("x", MaxProfileBytes+1),
	}
	for _, input := range invalid {
		if _, err := ParseProfile(input); err == nil {
			t.Fatalf("accepted invalid bundle %.80q", input)
		}
	}
}
