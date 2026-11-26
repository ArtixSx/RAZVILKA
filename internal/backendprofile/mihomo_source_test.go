package backendprofile

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func nativeSource(t *testing.T, edit func(map[string]any)) string {
	t.Helper()
	node := map[string]any{
		"type": "vless", "server": "edge.example", "server_port": 443,
		"uuid": "123e4567-e89b-12d3-a456-426614174000",
		"tls":  map[string]any{"enabled": true, "server_name": "edge.example"},
	}
	edit(node)
	data, err := json.Marshal(map[string]any{"outbounds": []any{node}})
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func TestMihomoRefusesOptionsHiddenByNativeNormalization(t *testing.T) {
	cases := map[string]func(map[string]any){
		"tls certificate pin": func(n map[string]any) {
			n["tls"].(map[string]any)["certificate_public_key_sha256"] = []string{"secret-pin"}
		},
		"tls client key":        func(n map[string]any) { n["tls"].(map[string]any)["key_path"] = "/private/client.key" },
		"tls unknown type":      func(n map[string]any) { n["tls"].(map[string]any)["server_name"] = true },
		"tls bad alpn":          func(n map[string]any) { n["tls"].(map[string]any)["alpn"] = []any{"h2", 3} },
		"detour":                func(n map[string]any) { n["detour"] = "mandatory-upstream" },
		"wrong protocol option": func(n map[string]any) { n["password"] = "secret-other-protocol" },
		"early data":            func(n map[string]any) { n["transport"] = map[string]any{"type": "ws", "max_early_data": 2048} },
		"bad websocket header": func(n map[string]any) {
			n["transport"] = map[string]any{"type": "ws", "headers": map[string]any{"Host": []any{"edge.example"}}}
		},
		"bad grpc name": func(n map[string]any) { n["transport"] = map[string]any{"type": "grpc", "service_name": false} },
	}
	for name, edit := range cases {
		t.Run(name, func(t *testing.T) {
			raw := nativeSource(t, edit)
			for _, content := range []string{raw, base64.StdEncoding.EncodeToString([]byte(raw))} {
				result, err := Mihomo(content, MihomoOptions{SOCKSPort: 18090})
				if err == nil || result.Config != "" {
					t.Fatal("export silently removed required source settings")
				}
				if strings.Contains(err.Error(), "secret-") || strings.Contains(err.Error(), "/private/") {
					t.Fatal("error disclosed a source value")
				}
			}
		})
	}
}

func TestMihomoRefusesOptionsHiddenByClashNormalization(t *testing.T) {
	cases := map[string]func(map[string]any){
		"tls pin":        func(n map[string]any) { n["fingerprint"] = "secret-pin" },
		"tls client key": func(n map[string]any) { n["private-key"] = "secret-key" },
		"UDP disabled":   func(n map[string]any) { n["udp"] = false },
		"early data":     func(n map[string]any) { n["network"] = "ws"; n["ws-opts"] = map[string]any{"max-early-data": 2048} },
		"lost header": func(n map[string]any) {
			n["network"] = "ws"
			n["ws-opts"] = map[string]any{"headers": map[string]any{"Host": false}}
		},
		"transport mismatch": func(n map[string]any) { n["network"] = "grpc"; n["ws-opts"] = map[string]any{"path": "/required"} },
		"wrong alpn type":    func(n map[string]any) { n["alpn"] = "h2" },
		"detour":             func(n map[string]any) { n["dialer-proxy"] = "required-upstream" },
	}
	for name, edit := range cases {
		t.Run(name, func(t *testing.T) {
			node := map[string]any{"type": "vless", "server": "edge.example", "port": 443, "uuid": "123e4567-e89b-12d3-a456-426614174000", "tls": true}
			edit(node)
			data, err := yaml.Marshal(map[string]any{"proxies": []any{node}})
			if err != nil {
				t.Fatal(err)
			}
			for _, raw := range []string{string(data), base64.StdEncoding.EncodeToString(data)} {
				if _, err := Mihomo(raw, MihomoOptions{SOCKSPort: 18090}); err == nil {
					t.Fatal("export silently removed source settings")
				}
			}
		})
	}
}

func TestMihomoPreservesSupportedClashParameters(t *testing.T) {
	for _, protocol := range []string{
		`{type: vless, uuid: 123e4567-e89b-12d3-a456-426614174000, tls: true, sni: cover.example, network: tcp, skip-cert-verify: false}`,
		`{type: vless, uuid: 123e4567-e89b-12d3-a456-426614174000, tls: true, network: ws, ws-opts: {path: /ws, headers: {Host: cover.example}}}`,
		`{type: vless, uuid: 123e4567-e89b-12d3-a456-426614174000, tls: true, network: grpc, grpc-opts: {grpc-service-name: service}}`,
		`{type: hy2, password: example-pass, sni: cover.example, alpn: [h3], obfs: salamander, obfs-password: example-obfs}`,
		`{type: tuic, uuid: 123e4567-e89b-12d3-a456-426614174000, password: example-pass, sni: cover.example, congestion-controller: bbr, udp-relay-mode: native}`,
		`{type: ss, cipher: aes-128-gcm, password: example-pass, udp: true}`,
	} {
		var node map[string]any
		if err := yaml.Unmarshal([]byte(protocol), &node); err != nil {
			t.Fatal(err)
		}
		node["server"], node["port"] = "edge.example", 443
		data, err := yaml.Marshal(map[string]any{"proxies": []any{node}})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Mihomo(string(data), MihomoOptions{SOCKSPort: 18090}); err != nil {
			t.Fatalf("supported configuration %s: %v", node["type"], err)
		}
	}
}

func TestMihomoRefusesUnsupportedSettingsOnDeduplicatedNode(t *testing.T) {
	raw := nativeSource(t, func(map[string]any) {})
	var document map[string]any
	_ = json.Unmarshal([]byte(raw), &document)
	nodes := document["outbounds"].([]any)
	clone := map[string]any{}
	for k, v := range nodes[0].(map[string]any) {
		clone[k] = v
	}
	clone["detour"] = "required-upstream"
	document["outbounds"] = append(nodes, clone)
	data, _ := json.Marshal(document)
	if _, err := Mihomo(string(data), MihomoOptions{SOCKSPort: 18090}); err == nil {
		t.Fatal("deduplication hid a mandatory option")
	}
}

func TestMihomoRefusesUnsupportedProtocolTLSOptions(t *testing.T) {
	for _, raw := range []string{
		`{"outbounds":[{"type":"hysteria2","server":"edge.example","server_port":443,"password":"example","tls":{"enabled":true,"utls":{"enabled":true,"fingerprint":"chrome"}}}]}`,
		`{"outbounds":[{"type":"shadowsocks","server":"edge.example","server_port":443,"method":"aes-128-gcm","password":"example","tls":{"enabled":true}}]}`,
		`{"outbounds":[{"type":"hysteria2","server":"edge.example","server_port":443,"password":"example","tls":{"enabled":true},"obfs":{"type":"salamander"}}]}`,
	} {
		if _, err := Mihomo(raw, MihomoOptions{SOCKSPort: 18090}); err == nil {
			t.Fatal("accepted an option without corresponding target behavior")
		}
	}
}

func TestMihomoRejectsSpecialAndMalformedEndpointHosts(t *testing.T) {
	for _, host := range []string{"100.64.0.1", "198.18.0.1", "192.0.2.1", "240.0.0.1", "0.1.2.3", "127.1", "1.2.3.999", "edge..example", "-edge.example", "edge.example:443", "edge.example\t", "edge.example?query", "fe80::1%eth0"} {
		t.Run(host, func(t *testing.T) {
			raw := nativeSource(t, func(n map[string]any) { n["server"] = host })
			if _, err := Mihomo(raw, MihomoOptions{SOCKSPort: 18090}); err == nil {
				t.Fatal("accepted non-public or malformed endpoint")
			}
		})
	}
	for _, host := range []string{"8.8.8.8", "2606:4700:4700::1111", "edge.example", "edge.example."} {
		raw := nativeSource(t, func(n map[string]any) { n["server"] = host })
		if _, err := Mihomo(raw, MihomoOptions{SOCKSPort: 18090}); err != nil {
			t.Fatalf("valid endpoint %s rejected: %v", host, err)
		}
	}
}
