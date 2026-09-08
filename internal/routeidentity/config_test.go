package routeidentity

import (
	"strings"
	"testing"
)

func TestStaticOutboundInspection(t *testing.T) {
	const node = `{"type":"vless","tag":"proxy","server":"node.example","server_port":443}`
	for _, tt := range []struct{ name, engine, config, want string }{
		{"simple", "sing-box", `{"outbounds":[` + node + `]}`, "vless"},
		{"unused-direct", "sing-box", `{"outbounds":[{"type":"direct","tag":"direct"},` + node + `],"route":{"final":"proxy"}}`, "vless"},
		{"default-direct", "sing-box", `{"outbounds":[{"type":"direct","tag":"direct"},` + node + `]}`, "route-direct-outbound"},
		{"explicit-direct", "sing-box", `{"outbounds":[` + node + `,{"type":"direct","tag":"direct"}],"route":{"final":"direct"}}`, "route-direct-outbound"},
		{"direct-rule", "sing-box", `{"outbounds":[` + node + `],"route":{"rules":[{"domain":["telegram.org"],"outbound":"direct"}]}}`, "route-rules-unverified"},
		{"selector", "sing-box", `{"outbounds":[{"type":"selector","outbounds":["proxy","direct"]},` + node + `]}`, "route-outbound-unsupported"},
		{"urltest", "sing-box", `{"outbounds":[{"type":"urltest","outbounds":["proxy"]},` + node + `]}`, "route-outbound-unsupported"},
		{"missing-final", "sing-box", `{"outbounds":[` + node + `],"route":{"final":"absent"}}`, "route-outbound-missing"},
		{"invalid-final", "sing-box", `{"outbounds":[` + node + `],"route":{"final":false}}`, "route-config-invalid"},
		{"duplicate-tag", "sing-box", `{"outbounds":[` + node + `,` + node + `]}`, "route-outbound-ambiguous"},
		{"detour", "sing-box", `{"outbounds":[{"type":"vless","detour":"direct"}]}`, "route-chain-unverified"},
		{"api", "sing-box", `{"outbounds":[` + node + `],"experimental":{"clash_api":{}}}`, "route-dynamic-config-unverified"},
		{"nil-outbound", "sing-box", `{"outbounds":[null]}`, "route-outbound-unsupported"},
		{"invalid-json", "sing-box", `{broken`, "route-config-invalid"},
		{"local-relay", "sing-box", `{"outbounds":[{"type":"socks","server":"127.0.0.1","server_port":1080}]}`, "route-remote-endpoint-unverified"},
		{"local-name", "sing-box", `{"outbounds":[{"type":"socks","server":"relay.localhost.","server_port":1080}]}`, "route-remote-endpoint-unverified"},
		{"private-relay", "sing-box", `{"outbounds":[{"type":"socks","server":"192.168.1.1","server_port":1080}]}`, "route-remote-endpoint-unverified"},
		{"no-endpoint", "sing-box", `{"outbounds":[{"type":"socks"}]}`, "route-remote-endpoint-unverified"},
		{"xray", "xray", `{"outbounds":[{"protocol":"vless","settings":{"vnext":[{"address":"node.example","port":443}]}}]}`, "vless"},
		{"xray-direct", "xray", `{"outbounds":[{"protocol":"freedom"}]}`, "route-direct-outbound"},
		{"xray-does-not-support-final", "xray", `{"outbounds":[{"protocol":"freedom","tag":"direct"},{"protocol":"vless","tag":"proxy"}],"routing":{"final":"proxy"}}`, "route-config-invalid"},
		{"xray-balancer", "xray", `{"outbounds":[{"protocol":"vless"}],"routing":{"balancers":[{"tag":"pool"}]}}`, "route-rules-unverified"},
		{"xray-chain", "xray", `{"outbounds":[{"protocol":"vless","proxySettings":{"tag":"relay"}}]}`, "route-chain-unverified"},
		{"xray-dialer", "xray", `{"outbounds":[{"protocol":"vless","streamSettings":{"sockopt":{"dialerProxy":"relay"}}}]}`, "route-chain-unverified"},
		{"usque", "usque", `{"private_key":"SECRET","endpoint_pub_key":"PUB","id":"ID","access_token":"TOKEN"}`, "masque"},
		{"usque-incomplete", "usque", `{"private_key":"SECRET"}`, "route-config-invalid"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ConfigOutbound(tt.engine, []byte(tt.config))
			if err != nil {
				got = err.Error()
			}
			if got != tt.want {
				t.Fatalf("got %q, want %q", got, tt.want)
			}
			if strings.Contains(got, "SECRET") || strings.Contains(got, "node.example") {
				t.Fatal("config values leaked")
			}
		})
	}
}
