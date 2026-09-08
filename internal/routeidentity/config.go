// Package routeidentity records local runtime ownership. It does not claim to
// independently observe packets at a remote VPN exit.
package routeidentity

import (
	"encoding/json"
	"errors"
	"net"
	"strings"
)

// ConfigOutbound accepts only a static, unambiguous remote exit. Complex user
// routing must not be silently flattened or treated as proof of this exit.
// An unused DIRECT entry is allowed; an active DIRECT path is not.
func ConfigOutbound(engine string, data []byte) (string, error) {
	var doc map[string]json.RawMessage
	if json.Unmarshal(data, &doc) != nil || doc == nil {
		return "", errors.New("route-config-invalid")
	}
	if engine == "usque" {
		for _, key := range []string{"private_key", "endpoint_pub_key", "id", "access_token"} {
			var value string
			if json.Unmarshal(doc[key], &value) != nil || value == "" {
				return "", errors.New("route-config-invalid")
			}
		}
		return "masque", nil
	}
	if engine != "sing-box" && engine != "xray" {
		return "", errors.New("route-engine-unsupported")
	}
	var outs []map[string]json.RawMessage
	if json.Unmarshal(doc["outbounds"], &outs) != nil || len(outs) == 0 {
		return "", errors.New("route-outbound-missing")
	}
	routeKey, protocolKey := "route", "type"
	if engine == "xray" {
		routeKey, protocolKey = "routing", "protocol"
	}
	var routing map[string]json.RawMessage
	if raw, ok := doc[routeKey]; ok && json.Unmarshal(raw, &routing) != nil {
		return "", errors.New("route-config-invalid")
	}
	for _, key := range []string{"rules", "balancers"} {
		if raw, ok := routing[key]; ok {
			var list []json.RawMessage
			if json.Unmarshal(raw, &list) != nil || len(list) != 0 {
				return "", errors.New("route-rules-unverified")
			}
		}
	}
	// Runtime control APIs can switch routing without changing the config file.
	for _, key := range []string{"experimental", "api", "services", "endpoints"} {
		if _, ok := doc[key]; ok {
			return "", errors.New("route-dynamic-config-unverified")
		}
	}
	selected := outs[0]
	final := jsonText(routing["final"])
	if raw, ok := routing["final"]; ok {
		var value string
		if engine != "sing-box" || json.Unmarshal(raw, &value) != nil {
			return "", errors.New("route-config-invalid")
		}
	}
	tags := map[string]bool{}
	found := final == ""
	for _, out := range outs {
		tag := jsonText(out["tag"])
		if tag != "" && tags[tag] {
			return "", errors.New("route-outbound-ambiguous")
		}
		tags[tag] = true
		if final != "" && tag == final {
			selected, found = out, true
		}
	}
	if !found {
		return "", errors.New("route-outbound-missing")
	}
	protocol := jsonText(selected[protocolKey])
	switch protocol {
	case "direct", "freedom":
		return "", errors.New("route-direct-outbound")
	case "vless", "vmess", "trojan", "shadowsocks", "socks", "http":
	case "hysteria", "hysteria2", "tuic", "ssh", "anytls":
		if engine != "sing-box" {
			return "", errors.New("route-outbound-unsupported")
		}
	default:
		// selector/urltest, DNS, WireGuard and chained profiles need separate
		// attestation adapters, not an assumed winning leaf.
		return "", errors.New("route-outbound-unsupported")
	}
	for _, key := range []string{"detour", "proxySettings", "dialerProxy"} {
		if _, ok := selected[key]; ok {
			return "", errors.New("route-chain-unverified")
		}
	}
	var stream map[string]json.RawMessage
	if raw, ok := selected["streamSettings"]; ok {
		if json.Unmarshal(raw, &stream) != nil {
			return "", errors.New("route-config-invalid")
		}
		var sockopt map[string]json.RawMessage
		if raw, ok := stream["sockopt"]; ok {
			if json.Unmarshal(raw, &sockopt) != nil {
				return "", errors.New("route-config-invalid")
			}
			if _, ok := sockopt["dialerProxy"]; ok {
				return "", errors.New("route-chain-unverified")
			}
		}
	}
	if !remoteEndpoint(engine, protocol, selected) {
		return "", errors.New("route-remote-endpoint-unverified")
	}
	// Return a protocol identifier, never user-controlled tags or server secrets.
	return protocol, nil
}

func remoteEndpoint(engine, protocol string, out map[string]json.RawMessage) bool {
	host := jsonText(out["server"])
	var port int
	_ = json.Unmarshal(out["server_port"], &port)
	if engine == "xray" {
		var settings map[string]json.RawMessage
		if json.Unmarshal(out["settings"], &settings) != nil {
			return false
		}
		key := "servers"
		if protocol == "vless" || protocol == "vmess" {
			key = "vnext"
		}
		var servers []struct {
			Address string `json:"address"`
			Port    int    `json:"port"`
		}
		if json.Unmarshal(settings[key], &servers) != nil || len(servers) != 1 {
			return false
		}
		host, port = servers[0].Address, servers[0].Port
	}
	if host == "" || port < 1 || port > 65535 || strings.ContainsAny(host, "/\\:@ \t\r\n") {
		// A literal IPv6 endpoint is handled below, without brackets or a port.
		if net.ParseIP(host) == nil || port < 1 || port > 65535 {
			return false
		}
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsGlobalUnicast() && !ip.IsPrivate() && !ip.IsLoopback() && !ip.IsLinkLocalUnicast()
	}
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	return strings.Contains(host, ".") && host != "localhost" && !strings.HasSuffix(host, ".localhost") && !strings.HasSuffix(host, ".local")
}

func jsonText(raw json.RawMessage) string {
	var text string
	_ = json.Unmarshal(raw, &text)
	return text
}
