package providerprofile

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"
)

const (
	MaxProfileBytes = 256 << 10
	MaxNodes        = 64
)

type BundlePreview struct {
	Format    string    `json:"format"`
	EngineID  string    `json:"engine_id"`
	NodeCount int       `json:"node_count"`
	Nodes     []Preview `json:"nodes"`
	Warnings  []string  `json:"warnings,omitempty"`
}

type BundleResult struct {
	Preview BundlePreview
	Config  []byte
}

// ParseProfile accepts a single share URI, a plain-text/base64 subscription,
// a Clash/Mihomo YAML document, an array of share URIs, or a sing-box JSON
// document. Every accepted input is rebuilt into a small RAZVILKA-owned
// configuration; arbitrary inbounds, routing and DNS rules, services and
// experimental APIs from the source are ignored.
func ParseProfile(raw string) (BundleResult, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return BundleResult{}, errors.New("вставьте ссылку, подписку или JSON-профиль")
	}
	if len(raw) > MaxProfileBytes || strings.ContainsRune(raw, '\x00') || !utf8.ValidString(raw) {
		return BundleResult{}, errors.New("профиль слишком большой или содержит недопустимые данные")
	}

	outbounds, nodes, format, warnings, err := parseProfileContent(raw)
	if err != nil {
		decoded := decodeSubscription(raw)
		if decoded == "" || decoded == raw {
			return BundleResult{}, err
		}
		outbounds, nodes, format, warnings, err = parseProfileContent(decoded)
		if err != nil {
			return BundleResult{}, errors.New("не удалось разобрать закодированную подписку")
		}
		format = "base64-" + format
	}
	if len(nodes) == 0 {
		return BundleResult{}, errors.New("в профиле нет поддерживаемых узлов")
	}
	if len(nodes) > MaxNodes {
		return BundleResult{}, fmt.Errorf("в профиле %d узлов; допустимо не более %d", len(nodes), MaxNodes)
	}

	config, err := buildBundleConfig(outbounds)
	if err != nil {
		return BundleResult{}, err
	}
	preview := BundlePreview{Format: format, EngineID: "sing-box", NodeCount: len(nodes), Nodes: nodes, Warnings: warnings}
	if len(nodes) > 1 {
		preview.Warnings = append(preview.Warnings, "После импорта активным будет первый узел. Остальные сохранятся в локальном селекторе Sing-box.")
	}
	return BundleResult{Preview: preview, Config: config}, nil
}

func parseProfileContent(raw string) ([]map[string]any, []Preview, string, []string, error) {
	trimmed := strings.TrimSpace(raw)
	if strings.HasPrefix(trimmed, "{") || strings.HasPrefix(trimmed, "[") {
		outbounds, nodes, format, err := parseJSONProfile([]byte(trimmed))
		return outbounds, nodes, format, nil, err
	}
	if looksLikeClashYAML(trimmed) {
		return parseClashYAML([]byte(trimmed))
	}
	lines := subscriptionLines(trimmed)
	if len(lines) == 0 {
		return nil, nil, "", nil, errors.New("подписка не содержит ссылок")
	}
	if len(lines) > MaxNodes {
		return nil, nil, "", nil, fmt.Errorf("в подписке больше %d строк", MaxNodes)
	}
	outbounds := make([]map[string]any, 0, len(lines))
	nodes := make([]Preview, 0, len(lines))
	for index, line := range lines {
		outbound, preview, err := parseURIOutbound(line)
		if err != nil {
			return nil, nil, "", nil, fmt.Errorf("узел %d: %w", index+1, err)
		}
		outbounds = append(outbounds, outbound)
		nodes = append(nodes, preview)
	}
	format := "uri"
	if len(lines) > 1 {
		format = "text-subscription"
	}
	return outbounds, nodes, format, nil, nil
}

func subscriptionLines(raw string) []string {
	raw = strings.ReplaceAll(raw, "\r\n", "\n")
	raw = strings.ReplaceAll(raw, "\r", "\n")
	parts := strings.Split(raw, "\n")
	lines := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" || strings.HasPrefix(part, "#") || strings.HasPrefix(part, "//") {
			continue
		}
		lines = append(lines, part)
	}
	return lines
}

func decodeSubscription(raw string) string {
	raw = strings.TrimSpace(raw)
	if len(raw) > MaxProfileBytes {
		return ""
	}
	for _, encoding := range []*base64.Encoding{base64.RawStdEncoding, base64.StdEncoding, base64.RawURLEncoding, base64.URLEncoding} {
		decoded, err := encoding.DecodeString(raw)
		if err == nil && len(decoded) > 0 && len(decoded) <= MaxProfileBytes && utf8.Valid(decoded) {
			return strings.TrimSpace(string(decoded))
		}
	}
	return ""
}

func parseJSONProfile(data []byte) ([]map[string]any, []Preview, string, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var document any
	if err := decoder.Decode(&document); err != nil {
		return nil, nil, "", errors.New("JSON-профиль повреждён")
	}
	var entries []any
	format := "json"
	switch value := document.(type) {
	case []any:
		entries = value
	case map[string]any:
		if outbounds, ok := value["outbounds"].([]any); ok {
			entries = outbounds
			format = "sing-box-json"
		} else if uris, ok := value["uris"].([]any); ok {
			entries = uris
			format = "json-subscription"
		} else {
			return nil, nil, "", errors.New("JSON должен содержать outbounds или uris")
		}
	default:
		return nil, nil, "", errors.New("неподдерживаемая структура JSON-профиля")
	}
	if len(entries) > MaxNodes+8 {
		return nil, nil, "", fmt.Errorf("в JSON слишком много элементов; допустимо не более %d узлов", MaxNodes)
	}

	outbounds := make([]map[string]any, 0, len(entries))
	nodes := make([]Preview, 0, len(entries))
	for _, entry := range entries {
		switch value := entry.(type) {
		case string:
			outbound, preview, err := parseURIOutbound(value)
			if err != nil {
				return nil, nil, "", fmt.Errorf("JSON-ссылка %d: %w", len(nodes)+1, err)
			}
			outbounds = append(outbounds, outbound)
			nodes = append(nodes, preview)
		case map[string]any:
			typeName := strings.ToLower(stringField(value, "type"))
			if typeName == "direct" || typeName == "block" || typeName == "selector" || typeName == "urltest" {
				continue
			}
			outbound, preview, err := normalizeNativeOutbound(value)
			if err != nil {
				return nil, nil, "", fmt.Errorf("JSON-узел %d: %w", len(nodes)+1, err)
			}
			outbounds = append(outbounds, outbound)
			nodes = append(nodes, preview)
		default:
			return nil, nil, "", errors.New("JSON содержит неподдерживаемый элемент")
		}
		if len(nodes) > MaxNodes {
			return nil, nil, "", fmt.Errorf("в профиле больше %d поддерживаемых узлов", MaxNodes)
		}
	}
	return outbounds, nodes, format, nil
}

func normalizeNativeOutbound(source map[string]any) (map[string]any, Preview, error) {
	typeName := strings.ToLower(stringField(source, "type"))
	server := strings.TrimSpace(stringField(source, "server"))
	port, err := integerField(source, "server_port")
	if err != nil || server == "" || len(server) > 253 || strings.ContainsAny(server, " /\\") || port < 1 || port > 65535 {
		return nil, Preview{}, errors.New("некорректный адрес или порт сервера")
	}
	name := strings.TrimSpace(stringField(source, "tag"))
	if len(name) > 120 {
		name = name[:120]
	}
	outbound := map[string]any{"type": typeName, "server": server, "server_port": port}
	preview := Preview{Name: name, Server: server, Port: port, EngineID: "sing-box"}
	switch typeName {
	case "vless":
		uuid := stringField(source, "uuid")
		if !looksLikeUUID(uuid) {
			return nil, Preview{}, errors.New("VLESS-узел не содержит корректный UUID")
		}
		outbound["uuid"] = uuid
		copyFields(outbound, source, "flow", "packet_encoding")
		copySanitizedFields(outbound, source)
		preview.Protocol = "VLESS"
	case "hysteria2":
		if stringField(source, "password") == "" {
			return nil, Preview{}, errors.New("Hysteria2-узел не содержит пароль")
		}
		copyFields(outbound, source, "password", "up_mbps", "down_mbps", "brutal_debug")
		copySanitizedFields(outbound, source)
		if obfs := sanitizeMap(source["obfs"], "type", "password"); len(obfs) > 0 {
			outbound["obfs"] = obfs
		}
		preview.Protocol, preview.Transport, preview.Security = "Hysteria2", "QUIC", "TLS"
	case "tuic":
		if !looksLikeUUID(stringField(source, "uuid")) || stringField(source, "password") == "" {
			return nil, Preview{}, errors.New("TUIC-узел не содержит корректные UUID и пароль")
		}
		copyFields(outbound, source, "uuid", "password", "congestion_control", "udp_relay_mode", "udp_over_stream", "zero_rtt_handshake", "heartbeat")
		copySanitizedFields(outbound, source)
		preview.Protocol, preview.Transport, preview.Security = "TUIC", "QUIC", "TLS"
	case "shadowsocks":
		if stringField(source, "method") == "" || stringField(source, "password") == "" {
			return nil, Preview{}, errors.New("Shadowsocks-узел не содержит метод или пароль")
		}
		if stringField(source, "plugin") != "" || stringField(source, "plugin_opts") != "" {
			return nil, Preview{}, errors.New("Shadowsocks-plugin не импортируется автоматически: загрузите проверенный конфиг вручную")
		}
		copyFields(outbound, source, "method", "password", "network", "udp_over_tcp")
		copySanitizedFields(outbound, source)
		preview.Protocol, preview.Transport, preview.Security = "Shadowsocks", "TCP/UDP", stringField(source, "method")
	default:
		return nil, Preview{}, fmt.Errorf("тип outbound %q пока не поддерживается", typeName)
	}
	if tls, ok := source["tls"].(map[string]any); ok {
		preview.TLS = boolField(tls, "enabled") || typeName == "hysteria2" || typeName == "tuic"
		if reality, ok := tls["reality"].(map[string]any); ok && boolField(reality, "enabled") {
			preview.Security = "reality"
		}
		if boolField(tls, "insecure") {
			preview.Warnings = append(preview.Warnings, "Проверка сертификата отключена в исходном профиле.")
		}
	}
	if transport, ok := source["transport"].(map[string]any); ok && stringField(transport, "type") != "" {
		preview.Transport = stringField(transport, "type")
	}
	return outbound, preview, nil
}

func buildBundleConfig(outbounds []map[string]any) ([]byte, error) {
	items := make([]any, 0, len(outbounds)+2)
	if len(outbounds) == 1 {
		outbounds[0]["tag"] = "proxy"
		items = append(items, outbounds[0])
	} else {
		tags := make([]string, 0, len(outbounds))
		for index, outbound := range outbounds {
			tag := fmt.Sprintf("node-%02d", index+1)
			outbound["tag"] = tag
			tags = append(tags, tag)
		}
		items = append(items, map[string]any{"type": "selector", "tag": "proxy", "outbounds": tags, "default": tags[0]})
		for _, outbound := range outbounds {
			items = append(items, outbound)
		}
	}
	items = append(items, map[string]any{"type": "direct", "tag": "direct"})
	document := map[string]any{
		"log":       map[string]any{"level": "warn", "timestamp": true},
		"outbounds": items,
		"route":     map[string]any{"auto_detect_interface": true, "final": "proxy"},
	}
	config, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(config, '\n'), nil
}

func copyFields(destination, source map[string]any, names ...string) {
	for _, name := range names {
		if value, ok := source[name]; ok && value != nil {
			destination[name] = value
		}
	}
}

func copySanitizedFields(destination, source map[string]any) {
	if tls := sanitizeTLS(source["tls"]); len(tls) > 0 {
		destination["tls"] = tls
	}
	if transport := sanitizeMap(source["transport"], "type", "host", "path", "method", "headers", "service_name", "idle_timeout", "ping_timeout"); len(transport) > 0 {
		destination["transport"] = transport
	}
	if multiplex := sanitizeMap(source["multiplex"], "enabled", "protocol", "max_connections", "min_streams", "max_streams", "padding"); len(multiplex) > 0 {
		destination["multiplex"] = multiplex
	}
}

func sanitizeTLS(value any) map[string]any {
	tls := sanitizeMap(value, "enabled", "server_name", "insecure", "alpn", "min_version", "max_version", "cipher_suites")
	source, _ := value.(map[string]any)
	if source == nil {
		return tls
	}
	if utls := sanitizeMap(source["utls"], "enabled", "fingerprint"); len(utls) > 0 {
		tls["utls"] = utls
	}
	if reality := sanitizeMap(source["reality"], "enabled", "public_key", "short_id"); len(reality) > 0 {
		tls["reality"] = reality
	}
	return tls
}

func sanitizeMap(value any, names ...string) map[string]any {
	source, _ := value.(map[string]any)
	if source == nil {
		return nil
	}
	result := make(map[string]any)
	for _, name := range names {
		value, ok := source[name]
		if !ok || value == nil {
			continue
		}
		switch value.(type) {
		case string, bool, json.Number, float64, int, []any, []string, map[string]any:
			result[name] = value
		}
	}
	return result
}

func stringField(value map[string]any, key string) string {
	text, _ := value[key].(string)
	return strings.TrimSpace(text)
}

func integerField(value map[string]any, key string) (int, error) {
	switch number := value[key].(type) {
	case json.Number:
		parsed, err := strconv.Atoi(number.String())
		return parsed, err
	case float64:
		return int(number), nil
	case int:
		return number, nil
	default:
		return 0, errors.New("not an integer")
	}
}

func boolField(value map[string]any, key string) bool {
	result, _ := value[key].(bool)
	return result
}
