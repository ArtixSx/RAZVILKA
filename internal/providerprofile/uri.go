package providerprofile

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

const MaxURIBytes = 16 << 10

type Preview struct {
	Protocol  string   `json:"protocol"`
	Name      string   `json:"name,omitempty"`
	Server    string   `json:"server"`
	Port      int      `json:"port"`
	TLS       bool     `json:"tls"`
	Transport string   `json:"transport,omitempty"`
	Security  string   `json:"security,omitempty"`
	Warnings  []string `json:"warnings,omitempty"`
	EngineID  string   `json:"engine_id"`
}

type Result struct {
	Preview Preview
	Config  []byte
}

func ParseURI(raw string) (Result, error) {
	outbound, preview, err := parseURIOutbound(raw)
	if err != nil {
		return Result{}, err
	}
	preview.EngineID = "sing-box"
	document := map[string]any{
		"log":       map[string]any{"level": "warn", "timestamp": true},
		"outbounds": []any{outbound, map[string]any{"type": "direct", "tag": "direct"}},
		"route":     map[string]any{"auto_detect_interface": true},
	}
	config, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		return Result{}, err
	}
	return Result{Preview: preview, Config: append(config, '\n')}, nil
}

func parseURIOutbound(raw string) (map[string]any, Preview, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, Preview{}, errors.New("вставьте ссылку профиля")
	}
	if len(raw) > MaxURIBytes || strings.ContainsAny(raw, "\r\n\x00") {
		return nil, Preview{}, errors.New("ссылка слишком длинная или содержит недопустимые символы")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, Preview{}, errors.New("не удалось разобрать ссылку профиля")
	}
	var outbound map[string]any
	var preview Preview
	switch strings.ToLower(u.Scheme) {
	case "vless":
		outbound, preview, err = parseVLESS(u)
	case "hysteria2", "hy2":
		outbound, preview, err = parseHysteria2(u)
	case "tuic":
		outbound, preview, err = parseTUIC(u)
	case "ss":
		outbound, preview, err = parseShadowsocks(u)
	case "http", "https":
		err = errors.New("вставлена ссылка на сайт или подписку; откройте её и вставьте сам ключ vless://, hysteria2://, tuic:// или ss://")
	default:
		err = fmt.Errorf("протокол %q пока не поддерживается; используйте VLESS, Hysteria2, TUIC, Shadowsocks или импорт JSON", u.Scheme)
	}
	if err != nil {
		return nil, Preview{}, err
	}
	preview.EngineID = "sing-box"
	return outbound, preview, nil
}

func parseVLESS(u *url.URL) (map[string]any, Preview, error) {
	server, port, err := endpoint(u, 443)
	if err != nil {
		return nil, Preview{}, err
	}
	uuid := ""
	if u.User != nil {
		uuid = strings.TrimSpace(u.User.Username())
	}
	if !looksLikeUUID(uuid) {
		return nil, Preview{}, errors.New("в ссылке VLESS отсутствует корректный UUID")
	}
	q := u.Query()
	security := strings.ToLower(strings.TrimSpace(q.Get("security")))
	if security == "" {
		security = "none"
	}
	transport := strings.ToLower(strings.TrimSpace(q.Get("type")))
	if transport == "" {
		transport = "tcp"
	}
	out := map[string]any{"type": "vless", "tag": "proxy", "server": server, "server_port": port, "uuid": uuid}
	if flow := strings.TrimSpace(q.Get("flow")); flow != "" {
		out["flow"] = flow
	}
	if security == "tls" || security == "reality" {
		tls := tlsOptions(q, server)
		if security == "reality" {
			publicKey := strings.TrimSpace(first(q.Get("pbk"), q.Get("publicKey")))
			if publicKey == "" {
				return nil, Preview{}, errors.New("для VLESS Reality нужен публичный ключ pbk")
			}
			reality := map[string]any{"enabled": true, "public_key": publicKey}
			if shortID := strings.TrimSpace(first(q.Get("sid"), q.Get("shortId"))); shortID != "" {
				reality["short_id"] = shortID
			}
			tls["reality"] = reality
		}
		out["tls"] = tls
	}
	if value := transportOptions(q, transport); value != nil {
		out["transport"] = value
	}
	preview := Preview{Protocol: "VLESS", Name: profileName(u), Server: server, Port: port, TLS: security == "tls" || security == "reality", Transport: transport, Security: security}
	if insecure(q) {
		preview.Warnings = append(preview.Warnings, "Проверка сертификата отключена в исходном профиле.")
	}
	return out, preview, nil
}

func parseHysteria2(u *url.URL) (map[string]any, Preview, error) {
	server, port, err := endpoint(u, 443)
	if err != nil {
		return nil, Preview{}, err
	}
	password := userSecret(u, false)
	if password == "" {
		return nil, Preview{}, errors.New("в ссылке Hysteria2 отсутствует пароль")
	}
	q := u.Query()
	out := map[string]any{"type": "hysteria2", "tag": "proxy", "server": server, "server_port": port, "password": password, "tls": tlsOptions(q, server)}
	preview := Preview{Protocol: "Hysteria2", Name: profileName(u), Server: server, Port: port, TLS: true, Transport: "QUIC", Security: "TLS"}
	if insecure(q) {
		preview.Warnings = append(preview.Warnings, "Проверка сертификата отключена в исходном профиле.")
	}
	return out, preview, nil
}

func parseTUIC(u *url.URL) (map[string]any, Preview, error) {
	server, port, err := endpoint(u, 443)
	if err != nil {
		return nil, Preview{}, err
	}
	if u.User == nil {
		return nil, Preview{}, errors.New("в ссылке TUIC отсутствуют UUID и пароль")
	}
	uuid := strings.TrimSpace(u.User.Username())
	password, ok := u.User.Password()
	if !looksLikeUUID(uuid) || !ok || strings.TrimSpace(password) == "" {
		return nil, Preview{}, errors.New("в ссылке TUIC нужны корректные UUID и пароль")
	}
	q := u.Query()
	out := map[string]any{"type": "tuic", "tag": "proxy", "server": server, "server_port": port, "uuid": uuid, "password": password, "tls": tlsOptions(q, server)}
	if value := strings.TrimSpace(q.Get("congestion_control")); value != "" {
		out["congestion_control"] = value
	}
	preview := Preview{Protocol: "TUIC", Name: profileName(u), Server: server, Port: port, TLS: true, Transport: "QUIC", Security: "TLS"}
	if insecure(q) {
		preview.Warnings = append(preview.Warnings, "Проверка сертификата отключена в исходном профиле.")
	}
	return out, preview, nil
}

func parseShadowsocks(u *url.URL) (map[string]any, Preview, error) {
	q := u.Query()
	serverURL := u
	credential := ""
	if u.User != nil {
		credential = decodeBase64(u.User.Username())
		if credential == "" {
			credential = u.User.Username()
			if password, ok := u.User.Password(); ok {
				credential += ":" + password
			}
		}
	} else {
		decoded := decodeBase64(u.Host)
		if decoded == "" {
			return nil, Preview{}, errors.New("не удалось декодировать Shadowsocks-ссылку")
		}
		parsed, err := url.Parse("ss://" + decoded)
		if err != nil || parsed.User == nil {
			return nil, Preview{}, errors.New("некорректная Shadowsocks-ссылка")
		}
		serverURL = parsed
		credential = parsed.User.Username()
		if password, ok := parsed.User.Password(); ok {
			credential += ":" + password
		}
	}
	method, password, ok := strings.Cut(credential, ":")
	if !ok || strings.TrimSpace(method) == "" || password == "" {
		return nil, Preview{}, errors.New("в Shadowsocks-ссылке отсутствуют метод или пароль")
	}
	server, port, err := endpoint(serverURL, 8388)
	if err != nil {
		return nil, Preview{}, err
	}
	out := map[string]any{"type": "shadowsocks", "tag": "proxy", "server": server, "server_port": port, "method": method, "password": password}
	if plugin := strings.TrimSpace(q.Get("plugin")); plugin != "" {
		return nil, Preview{}, errors.New("Shadowsocks-plugin не импортируется автоматически: загрузите проверенный конфиг вручную")
	}
	return out, Preview{Protocol: "Shadowsocks", Name: profileName(u), Server: server, Port: port, Transport: "TCP/UDP", Security: method}, nil
}

func endpoint(u *url.URL, defaultPort int) (string, int, error) {
	server := strings.TrimSpace(u.Hostname())
	if server == "" || len(server) > 253 || strings.ContainsAny(server, " /\\") {
		return "", 0, errors.New("в профиле отсутствует корректный адрес сервера")
	}
	port := defaultPort
	if raw := u.Port(); raw != "" {
		value, err := strconv.Atoi(raw)
		if err != nil || value < 1 || value > 65535 {
			return "", 0, errors.New("в профиле указан некорректный порт")
		}
		port = value
	}
	return server, port, nil
}

func tlsOptions(q url.Values, server string) map[string]any {
	serverName := strings.TrimSpace(first(q.Get("sni"), q.Get("serverName")))
	if serverName == "" && net.ParseIP(server) == nil {
		serverName = server
	}
	tls := map[string]any{"enabled": true}
	if serverName != "" {
		tls["server_name"] = serverName
	}
	if insecure(q) {
		tls["insecure"] = true
	}
	if fingerprint := strings.TrimSpace(first(q.Get("fp"), q.Get("fingerprint"))); fingerprint != "" {
		tls["utls"] = map[string]any{"enabled": true, "fingerprint": fingerprint}
	}
	if alpn := splitNonEmpty(q.Get("alpn")); len(alpn) > 0 {
		tls["alpn"] = alpn
	}
	return tls
}

func transportOptions(q url.Values, kind string) map[string]any {
	switch kind {
	case "ws", "websocket":
		transport := map[string]any{"type": "ws"}
		if path := strings.TrimSpace(q.Get("path")); path != "" {
			transport["path"] = path
		}
		if host := strings.TrimSpace(q.Get("host")); host != "" {
			transport["headers"] = map[string]any{"Host": host}
		}
		return transport
	case "grpc":
		transport := map[string]any{"type": "grpc"}
		if service := strings.TrimSpace(first(q.Get("serviceName"), q.Get("service_name"))); service != "" {
			transport["service_name"] = service
		}
		return transport
	case "http", "h2":
		return map[string]any{"type": "http", "path": q.Get("path")}
	}
	return nil
}

func userSecret(u *url.URL, includeUsername bool) string {
	if u.User == nil {
		return ""
	}
	username := u.User.Username()
	password, hasPassword := u.User.Password()
	if includeUsername && hasPassword {
		return username + ":" + password
	}
	if hasPassword && password != "" {
		return password
	}
	return username
}

func profileName(u *url.URL) string {
	name, _ := url.PathUnescape(u.Fragment)
	name = strings.TrimSpace(name)
	if len(name) > 120 {
		name = name[:120]
	}
	return name
}

func insecure(q url.Values) bool {
	value := strings.ToLower(strings.TrimSpace(first(q.Get("insecure"), q.Get("allowInsecure"))))
	return value == "1" || value == "true" || value == "yes"
}

func looksLikeUUID(value string) bool {
	parts := strings.Split(value, "-")
	if len(parts) != 5 || len(parts[0]) != 8 || len(parts[1]) != 4 || len(parts[2]) != 4 || len(parts[3]) != 4 || len(parts[4]) != 12 {
		return false
	}
	for _, part := range parts {
		for _, r := range part {
			if !strings.ContainsRune("0123456789abcdefABCDEF", r) {
				return false
			}
		}
	}
	return true
}

func decodeBase64(value string) string {
	value = strings.TrimSpace(value)
	for _, encoding := range []*base64.Encoding{base64.RawURLEncoding, base64.URLEncoding, base64.RawStdEncoding, base64.StdEncoding} {
		if decoded, err := encoding.DecodeString(value); err == nil {
			return string(decoded)
		}
	}
	return ""
}

func splitNonEmpty(value string) []string {
	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, part)
		}
	}
	return out
}

func first(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}
