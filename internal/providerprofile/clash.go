package providerprofile

import (
	"errors"
	"fmt"
	"io"
	"strings"

	"gopkg.in/yaml.v3"
)

func looksLikeClashYAML(raw string) bool {
	for _, line := range strings.Split(strings.ReplaceAll(raw, "\r", ""), "\n") {
		line = strings.TrimSpace(line)
		if line == "proxies:" || strings.HasPrefix(line, "proxies: ") {
			return true
		}
	}
	return false
}

// parseClashYAML reads only the proxies list. Rules, DNS, proxy groups,
// providers, scripts and controller settings never reach the generated config.
func parseClashYAML(data []byte) ([]map[string]any, []Preview, string, []string, error) {
	decoder := yaml.NewDecoder(strings.NewReader(string(data)))
	var document map[string]any
	if err := decoder.Decode(&document); err != nil {
		return nil, nil, "", nil, errors.New("YAML Clash/Mihomo повреждён")
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return nil, nil, "", nil, errors.New("YAML с несколькими документами не поддерживается")
		}
		return nil, nil, "", nil, errors.New("YAML Clash/Mihomo повреждён")
	}
	entries, ok := document["proxies"].([]any)
	if !ok || len(entries) == 0 {
		return nil, nil, "", nil, errors.New("YAML должен содержать непустой список proxies")
	}
	if len(entries) > MaxNodes+64 {
		return nil, nil, "", nil, fmt.Errorf("в YAML слишком много proxies; допустимо не более %d поддерживаемых узлов", MaxNodes)
	}

	outbounds := make([]map[string]any, 0, len(entries))
	nodes := make([]Preview, 0, len(entries))
	skipped := 0
	for index, entry := range entries {
		proxy, ok := entry.(map[string]any)
		if !ok {
			return nil, nil, "", nil, fmt.Errorf("YAML proxy %d имеет неподдерживаемую структуру", index+1)
		}
		typeName := canonicalClashType(textValue(proxy["type"]))
		if typeName == "" {
			skipped++
			continue
		}
		source := clashProxyToNative(proxy, typeName)
		outbound, preview, err := normalizeNativeOutbound(source)
		if err != nil {
			return nil, nil, "", nil, fmt.Errorf("YAML proxy %d (%s): %w", index+1, safeProxyName(proxy), err)
		}
		outbounds = append(outbounds, outbound)
		nodes = append(nodes, preview)
		if len(nodes) > MaxNodes {
			return nil, nil, "", nil, fmt.Errorf("в YAML больше %d поддерживаемых узлов", MaxNodes)
		}
	}
	if len(nodes) == 0 {
		return nil, nil, "", nil, errors.New("в YAML нет поддерживаемых VLESS, Hysteria2, TUIC или Shadowsocks proxies")
	}
	warnings := []string{"Импортированы только поддерживаемые proxies. DNS, правила, группы, providers, скрипты и внешние панели Clash/Mihomo отброшены."}
	if skipped > 0 {
		warnings = append(warnings, fmt.Sprintf("Пропущено неподдерживаемых proxies: %d.", skipped))
	}
	return outbounds, nodes, "clash-mihomo-yaml", warnings, nil
}

func canonicalClashType(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "vless":
		return "vless"
	case "hysteria2", "hy2":
		return "hysteria2"
	case "tuic":
		return "tuic"
	case "ss", "shadowsocks":
		return "shadowsocks"
	default:
		return ""
	}
}

func clashProxyToNative(proxy map[string]any, typeName string) map[string]any {
	source := map[string]any{
		"type":        typeName,
		"tag":         textValue(proxy["name"]),
		"server":      textValue(proxy["server"]),
		"server_port": proxy["port"],
	}
	switch typeName {
	case "vless":
		source["uuid"] = textValue(proxy["uuid"])
		copyClashText(source, proxy, "flow", "flow")
		copyClashText(source, proxy, "packet_encoding", "packet-encoding")
	case "hysteria2":
		source["password"] = textValue(proxy["password"])
		if obfsType := textValue(proxy["obfs"]); obfsType != "" {
			source["obfs"] = map[string]any{"type": obfsType, "password": textValue(proxy["obfs-password"])}
		}
	case "tuic":
		source["uuid"] = textValue(proxy["uuid"])
		source["password"] = textValue(proxy["password"])
		copyClashText(source, proxy, "congestion_control", "congestion-controller")
		copyClashText(source, proxy, "udp_relay_mode", "udp-relay-mode")
	case "shadowsocks":
		source["method"] = textValue(proxy["cipher"])
		source["password"] = textValue(proxy["password"])
		copyClashText(source, proxy, "plugin", "plugin")
		copyClashText(source, proxy, "plugin_opts", "plugin-opts")
	}
	if tls := clashTLS(proxy, typeName); len(tls) > 0 {
		source["tls"] = tls
	}
	if transport := clashTransport(proxy); len(transport) > 0 {
		source["transport"] = transport
	}
	return source
}

func clashTLS(proxy map[string]any, typeName string) map[string]any {
	enabled := boolValue(proxy["tls"]) || typeName == "hysteria2" || typeName == "tuic"
	reality, _ := proxy["reality-opts"].(map[string]any)
	if len(reality) > 0 {
		enabled = true
	}
	if !enabled {
		return nil
	}
	tls := map[string]any{"enabled": true}
	if serverName := first(textValue(proxy["servername"]), textValue(proxy["sni"])); serverName != "" {
		tls["server_name"] = serverName
	}
	if insecure := boolValue(proxy["skip-cert-verify"]); insecure {
		tls["insecure"] = true
	}
	if alpn := stringList(proxy["alpn"]); len(alpn) > 0 {
		tls["alpn"] = alpn
	}
	if fingerprint := textValue(proxy["client-fingerprint"]); fingerprint != "" {
		tls["utls"] = map[string]any{"enabled": true, "fingerprint": fingerprint}
	}
	if len(reality) > 0 {
		value := map[string]any{"enabled": true}
		if publicKey := textValue(reality["public-key"]); publicKey != "" {
			value["public_key"] = publicKey
		}
		if shortID := textValue(reality["short-id"]); shortID != "" {
			value["short_id"] = shortID
		}
		tls["reality"] = value
	}
	return tls
}

func clashTransport(proxy map[string]any) map[string]any {
	network := strings.ToLower(textValue(proxy["network"]))
	switch network {
	case "ws":
		transport := map[string]any{"type": "ws"}
		if options, ok := proxy["ws-opts"].(map[string]any); ok {
			copyClashText(transport, options, "path", "path")
			if headers, ok := options["headers"].(map[string]any); ok && len(headers) > 0 {
				clean := make(map[string]any)
				for key, value := range headers {
					if text := textValue(value); text != "" && len(key) <= 80 && len(text) <= 512 {
						clean[key] = text
					}
				}
				if len(clean) > 0 {
					transport["headers"] = clean
				}
			}
		}
		return transport
	case "grpc":
		transport := map[string]any{"type": "grpc"}
		if options, ok := proxy["grpc-opts"].(map[string]any); ok {
			copyClashText(transport, options, "service_name", "grpc-service-name")
		}
		return transport
	case "http", "h2":
		return map[string]any{"type": "http"}
	default:
		return nil
	}
}

func copyClashText(destination, source map[string]any, destinationKey, sourceKey string) {
	if value := textValue(source[sourceKey]); value != "" {
		destination[destinationKey] = value
	}
}

func safeProxyName(proxy map[string]any) string {
	name := textValue(proxy["name"])
	if name == "" {
		return "без имени"
	}
	if len(name) > 80 {
		return name[:80]
	}
	return name
}

func textValue(value any) string {
	text, _ := value.(string)
	return strings.TrimSpace(text)
}

func boolValue(value any) bool {
	result, _ := value.(bool)
	return result
}

func stringList(value any) []string {
	items, ok := value.([]any)
	if !ok {
		return nil
	}
	result := make([]string, 0, len(items))
	for _, item := range items {
		if text := textValue(item); text != "" && len(text) <= 64 {
			result = append(result, text)
		}
	}
	return result
}
