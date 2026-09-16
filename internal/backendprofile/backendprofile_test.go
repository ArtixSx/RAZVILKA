package backendprofile

import (
	"encoding/json"
	"gopkg.in/yaml.v3"
	"strings"
	"testing"
)

const vless = "vless://123e4567-e89b-12d3-a456-426614174000@edge.example:443?security=tls&sni=edge.example&type=tcp"

func TestMihomoIsLocalPassiveAndSingleSelected(t *testing.T) {
	r, e := Mihomo(vless, MihomoOptions{SOCKSPort: 18090})
	if e != nil {
		t.Fatal(e)
	}
	var doc map[string]any
	if yaml.Unmarshal([]byte(r.Config), &doc) != nil {
		t.Fatal("yaml")
	}
	if doc["allow-lan"] != false || doc["bind-address"] != "127.0.0.1" || doc["socks-port"] != 18090 {
		t.Fatal(doc)
	}
	for _, key := range []string{"external-controller", "external-ui-url", "proxy-providers", "script", "rule-providers"} {
		if _, ok := doc[key]; ok {
			t.Fatal("source authority copied", key)
		}
	}
	if r.LiveApplied || r.NativeValidated || r.ServiceVerified {
		t.Fatal("unearned proof")
	}
	proxy := doc["proxies"].([]any)[0].(map[string]any)
	if proxy["type"] != "vless" || proxy["uuid"] != "123e4567-e89b-12d3-a456-426614174000" || proxy["tls"] != true {
		t.Fatal(proxy)
	}
}
func TestMihomoPreservesTransports(t *testing.T) {
	for _, kind := range []string{"ws", "grpc"} {
		t.Run(kind, func(t *testing.T) {
			raw := strings.Replace(vless, "type=tcp", "type="+kind+"&path=%2Fproxy&serviceName=grpc-service", 1)
			// URI validation correctly forbids parameters irrelevant to the selected transport.
			if kind == "ws" {
				raw = strings.Replace(raw, "&serviceName=grpc-service", "", 1)
			} else {
				raw = strings.Replace(raw, "&path=%2Fproxy", "", 1)
			}
			r, e := Mihomo(raw, MihomoOptions{SOCKSPort: 18090})
			if e != nil {
				t.Fatal(e)
			}
			if !strings.Contains(r.Config, "network: "+kind) {
				t.Fatal(r.Config)
			}
		})
	}
}
func TestMihomoRejectsUnsupportedOrUnsafe(t *testing.T) {
	for _, raw := range []string{strings.Replace(vless, "type=tcp", "type=xhttp", 1), strings.Replace(vless, "edge.example:443", "127.0.0.1:443", 1), vless + "&allowInsecure=1", "proxies:\n - {type: unknown, server: example.org, port: 1}", "https://subscription.example/list"} {
		t.Run(raw, func(t *testing.T) {
			if _, e := Mihomo(raw, MihomoOptions{SOCKSPort: 18090}); e == nil {
				t.Fatal("accepted")
			}
		})
	}
	for _, port := range []int{0, 53, 65536} {
		if _, e := Mihomo(vless, MihomoOptions{SOCKSPort: port}); e == nil {
			t.Fatal("port")
		}
	}
	if _, e := Mihomo(vless, MihomoOptions{SOCKSPort: 18090, Index: 1}); e == nil {
		t.Fatal("index")
	}
}
func TestMihomoDropsSourceNetworkAuthority(t *testing.T) {
	raw := `allow-lan: true
external-controller: 0.0.0.0:9090
external-ui-url: https://bad.example/panel.zip
proxy-providers:
  bad: {type: http, url: https://bad.example/subscription}
tun: {enable: true, auto-route: true}
dns: {enable: true, listen: 0.0.0.0:53}
proxies:
 - {name: input, type: vless, server: edge.example, port: 443, uuid: 123e4567-e89b-12d3-a456-426614174000, tls: true}
`
	r, e := Mihomo(raw, MihomoOptions{SOCKSPort: 18090})
	if e != nil {
		t.Fatal(e)
	}
	if strings.Contains(r.Config, "bad.example") || strings.Contains(r.Config, "auto-route") || strings.Contains(r.Config, "0.0.0.0") {
		t.Fatal(r.Config)
	}
}
func TestHevBoundedSafeConfig(t *testing.T) {
	o := HevOptions{Interface: "rz-sing", Address: "172.31.21.1/30", SOCKSPort: 18081, MTU: 1400, MaxSessions: 128}
	data, e := HevJSON(o)
	if e != nil {
		t.Fatal(e)
	}
	var doc map[string]any
	if json.Unmarshal(data, &doc) != nil {
		t.Fatal("json")
	}
	if doc["tunnel"].(map[string]any)["icmp"] != "off" || doc["socks5"].(map[string]any)["address"] != "127.0.0.1" {
		t.Fatal(doc)
	}
	for _, bad := range []string{"post-up-script", "pre-down-script", "pid-file", "mapdns"} {
		if strings.Contains(string(data), bad) {
			t.Fatal(bad)
		}
	}
	for _, edit := range []func(*HevOptions){func(x *HevOptions) { x.Interface = "eth0" }, func(x *HevOptions) { x.Address = "8.8.8.8/30" }, func(x *HevOptions) { x.Address = "172.31.21.1/8" }, func(x *HevOptions) { x.MTU = 9000 }, func(x *HevOptions) { x.MaxSessions = 0 }, func(x *HevOptions) { x.SOCKSPort = 53 }} {
		x := o
		edit(&x)
		if _, e := HevJSON(x); e == nil {
			t.Fatal(x)
		}
	}
}
func TestMihomoMoreProtocolsAndReality(t *testing.T) {
	cases := []struct {
		raw      string
		contains []string
	}{
		{"hy2://testpass@edge.example:443?sni=edge.example&obfs=salamander&obfs-password=obfspass", []string{"type: hysteria2", "password: testpass", "obfs: salamander", "obfs-password: obfspass"}},
		{"tuic://123e4567-e89b-12d3-a456-426614174000:testpass@edge.example:443?sni=edge.example&congestion_control=bbr", []string{"type: tuic", "congestion-controller: bbr"}},
		{"ss://YWVzLTEyOC1nY206dGVzdHBhc3M@edge.example:443", []string{"type: ss", "cipher: aes-128-gcm", "password: testpass"}},
		{"vless://123e4567-e89b-12d3-a456-426614174000@edge.example:443?security=reality&sni=cover.example&pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&sid=abcd&fp=chrome&type=tcp", []string{"reality-opts:", "public-key:", "short-id: abcd", "client-fingerprint: chrome"}},
	}
	for _, c := range cases {
		t.Run(c.contains[0], func(t *testing.T) {
			r, e := Mihomo(c.raw, MihomoOptions{SOCKSPort: 18090})
			if e != nil {
				t.Fatal(e)
			}
			for _, s := range c.contains {
				if !strings.Contains(r.Config, s) {
					t.Fatalf("missing %s in %s", s, r.Config)
				}
			}
		})
	}
}
func TestMihomoSelectedNodeOnlyNoFalsePoolWarning(t *testing.T) {
	raw := vless + "\n" + strings.ReplaceAll(vless, "edge.example", "second.example")
	r, e := Mihomo(raw, MihomoOptions{Index: 1, SOCKSPort: 18090})
	if e != nil || !strings.Contains(r.Config, "second.example") || strings.Contains(r.Config, "edge.example") {
		t.Fatal(e, r.Config)
	}
	if strings.Contains(strings.Join(r.Source.Warnings, " "), "Sing-box") {
		t.Fatal("foreign behavior claim")
	}
}
