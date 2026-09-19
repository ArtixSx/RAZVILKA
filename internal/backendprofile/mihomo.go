// Package backendprofile builds bounded, passive configurations for optional
// executors. It does not start processes, fetch subscriptions or change routes.
package backendprofile

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strings"

	"github.com/ArtixSx/razvilka/internal/providerprofile"
	"github.com/ArtixSx/razvilka/internal/publicfetch"
	"gopkg.in/yaml.v3"
)

var ErrUnsupported = errors.New("configuration cannot be represented without losing required parameters")

type MihomoOptions struct {
	Index     int `json:"index"`
	SOCKSPort int `json:"socks_port"`
}
type MihomoResult struct {
	Config          string                        `json:"config"`
	Source          providerprofile.BundlePreview `json:"source"`
	Protocol        string                        `json:"protocol"`
	SOCKSPort       int                           `json:"socks_port"`
	NativeValidated bool                          `json:"native_validated"`
	ServiceVerified bool                          `json:"service_verified"`
	LiveApplied     bool                          `json:"live_applied"`
}

// Mihomo takes only a normalized supported outbound, never the original DNS,
// TUN, listeners, hooks, provider URLs or external-controller settings.
// A successful conversion is NOT native validation or service proof.
func Mihomo(raw string, options MihomoOptions) (MihomoResult, error) {
	var result MihomoResult
	if options.SOCKSPort < 1024 || options.SOCKSPort > 65535 {
		return result, ErrUnsupported
	}
	bundle, err := providerprofile.ParseProfileWithSelection(raw, options.Index)
	if err != nil {
		return result, err
	}
	// No partial acceptance behind an apparently successful conversion.
	if len(bundle.Preview.Rejected) != 0 {
		return result, ErrUnsupported
	}
	// The general importer deliberately normalizes only its supported subset.
	// Validate original node options before that normalization can hide a TLS
	// pin, transport option or other requirement this exporter cannot retain.
	if err := validateMihomoSource(raw, bundle.Preview.Format); err != nil {
		return result, err
	}
	var doc struct {
		Outbounds []map[string]any `json:"outbounds"`
	}
	if json.Unmarshal(bundle.Config, &doc) != nil {
		return result, ErrUnsupported
	}
	nodes := []map[string]any{}
	for _, outbound := range doc.Outbounds {
		switch outbound["type"] {
		case "selector", "urltest", "direct", "block":
			continue
		}
		nodes = append(nodes, outbound)
	}
	if options.Index < 0 || options.Index >= len(nodes) {
		return result, ErrUnsupported
	}
	node, err := mihomoNode(nodes[options.Index])
	if err != nil {
		return result, err
	}
	config := map[string]any{
		"socks-port": options.SOCKSPort, "allow-lan": false, "bind-address": "127.0.0.1",
		"mode": "rule", "log-level": "warning", "ipv6": false,
		"find-process-mode": "off", "geo-auto-update": false,
		"dns": map[string]any{"enable": false}, "tun": map[string]any{"enable": false},
		"sniffer": map[string]any{"enable": false},
		"profile": map[string]any{"store-selected": false, "store-fake-ip": false},
		"proxies": []any{node}, "rules": []string{"MATCH,rz-node"},
	}
	data, err := yaml.Marshal(config)
	if err != nil {
		return result, err
	}
	result.Config = string(data)
	result.Source = bundle.Preview
	result.Source.EngineID = "mihomo"
	result.Source.Warnings = []string{
		"Сформирован только выбранный узел. DNS/TUN/API и фоновые загрузки исходника не включены. Нужны mihomo -t и отдельный сервисный тест."}
	result.Protocol, _ = node["type"].(string)
	result.SOCKSPort = options.SOCKSPort
	return result, nil
}

func allowed(m map[string]any, fields ...string) bool {
	for k := range m {
		found := false
		for _, f := range fields {
			if k == f {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}
func str(m map[string]any, k string) string { s, _ := m[k].(string); return s }
func copyIf(dst, src map[string]any, from, to string) {
	if v, ok := src[from]; ok {
		dst[to] = v
	}
}
func publicHost(host string) bool {
	if host == "" || strings.ContainsAny(host, " /\\\x00\r\n") {
		return false
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		return publicfetch.PublicAddress(ip)
	}
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	for _, suffix := range []string{"localhost", ".localhost", ".local", ".lan", ".internal", ".home.arpa", ".onion"} {
		if host == suffix || strings.HasSuffix(host, suffix) {
			return false
		}
	}
	if len(host) > 253 || !strings.Contains(host, ".") {
		return false
	}
	numeric := true
	for _, label := range strings.Split(host, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if c >= 'a' && c <= 'z' || c == '-' {
				numeric = false
			} else if c < '0' || c > '9' {
				return false
			}
		}
	}
	// Do not let abbreviated or malformed IP literals enter through DNS syntax.
	return !numeric
}
func mihomoNode(src map[string]any) (map[string]any, error) {
	kind := str(src, "type")
	fields := []string{"type", "tag", "server", "server_port"}
	switch kind {
	case "vless":
		fields = append(fields, "uuid", "flow", "packet_encoding", "tls", "transport")
	case "hysteria2":
		fields = append(fields, "password", "tls", "obfs")
	case "tuic":
		fields = append(fields, "uuid", "password", "tls", "congestion_control", "udp_relay_mode")
	case "shadowsocks":
		fields = append(fields, "method", "password")
	default:
		return nil, ErrUnsupported
	}
	if !allowed(src, fields...) || !publicHost(str(src, "server")) {
		return nil, ErrUnsupported
	}
	for _, field := range []string{"uuid", "password", "method", "flow", "packet_encoding", "congestion_control", "udp_relay_mode"} {
		if value, exists := src[field]; exists {
			if _, ok := value.(string); !ok {
				return nil, ErrUnsupported
			}
		}
	}
	if kind == "hysteria2" || kind == "tuic" {
		if _, exists := src["tls"]; !exists {
			return nil, ErrUnsupported
		}
	}
	dst := map[string]any{"name": "rz-node", "type": kind, "server": src["server"], "port": src["server_port"], "udp": true}
	if kind == "shadowsocks" {
		dst["type"] = "ss"
		copyIf(dst, src, "method", "cipher")
	}
	for _, k := range []string{"uuid", "password", "flow"} {
		copyIf(dst, src, k, k)
	}
	copyIf(dst, src, "packet_encoding", "packet-encoding")
	copyIf(dst, src, "congestion_control", "congestion-controller")
	copyIf(dst, src, "udp_relay_mode", "udp-relay-mode")
	if raw, ok := src["tls"]; ok {
		tls, ok := raw.(map[string]any)
		if !ok || !allowed(tls, "enabled", "server_name", "alpn", "utls", "reality", "insecure") || tls["enabled"] != true {
			return nil, ErrUnsupported
		}
		if insecure, exists := tls["insecure"]; exists && insecure != false {
			return nil, ErrUnsupported
		}
		if sni, exists := tls["server_name"]; exists {
			if _, ok := sni.(string); !ok {
				return nil, ErrUnsupported
			}
		}
		if alpn, exists := tls["alpn"]; exists && !stringSequence(alpn) {
			return nil, ErrUnsupported
		}
		if kind == "vless" {
			dst["tls"] = true
			copyIf(dst, tls, "server_name", "servername")
		} else {
			copyIf(dst, tls, "server_name", "sni")
		}
		copyIf(dst, tls, "alpn", "alpn")
		if u, ok := tls["utls"]; ok {
			m, ok := u.(map[string]any)
			if !ok || kind != "vless" || !allowed(m, "enabled", "fingerprint") || m["enabled"] != true || str(m, "fingerprint") == "" {
				return nil, ErrUnsupported
			}
			copyIf(dst, m, "fingerprint", "client-fingerprint")
		}
		if r, ok := tls["reality"]; ok {
			m, ok := r.(map[string]any)
			if !ok || kind != "vless" || !allowed(m, "enabled", "public_key", "short_id") || m["enabled"] != true || str(m, "public_key") == "" {
				return nil, ErrUnsupported
			}
			if shortID, exists := m["short_id"]; exists {
				if _, ok := shortID.(string); !ok {
					return nil, ErrUnsupported
				}
			}
			v := map[string]any{}
			copyIf(v, m, "public_key", "public-key")
			copyIf(v, m, "short_id", "short-id")
			dst["reality-opts"] = v
		}
	}
	if raw, ok := src["obfs"]; ok {
		m, ok := raw.(map[string]any)
		if !ok || kind != "hysteria2" || !allowed(m, "type", "password") || str(m, "type") != "salamander" || str(m, "password") == "" {
			return nil, ErrUnsupported
		}
		dst["obfs"] = "salamander"
		copyIf(dst, m, "password", "obfs-password")
	}
	if raw, ok := src["transport"]; ok {
		t, ok := raw.(map[string]any)
		if !ok || kind != "vless" {
			return nil, ErrUnsupported
		}
		switch str(t, "type") {
		case "ws":
			if !allowed(t, "type", "path", "headers") {
				return nil, ErrUnsupported
			}
			if path, exists := t["path"]; exists {
				if _, ok := path.(string); !ok {
					return nil, ErrUnsupported
				}
			}
			if headers, exists := t["headers"]; exists && !stringMapping(headers) {
				return nil, ErrUnsupported
			}
			ws := map[string]any{}
			copyIf(ws, t, "path", "path")
			copyIf(ws, t, "headers", "headers")
			dst["network"] = "ws"
			dst["ws-opts"] = ws
		case "grpc":
			if !allowed(t, "type", "service_name") {
				return nil, ErrUnsupported
			}
			if service, exists := t["service_name"]; exists {
				if _, ok := service.(string); !ok {
					return nil, ErrUnsupported
				}
			}
			opts := map[string]any{}
			copyIf(opts, t, "service_name", "grpc-service-name")
			dst["network"] = "grpc"
			dst["grpc-opts"] = opts
		default:
			return nil, fmt.Errorf("%w: transport", ErrUnsupported)
		}
	}
	return dst, nil
}
