package providerprofile

import (
	"encoding/json"
	"errors"
	"net/url"
	"strings"
	"unicode/utf8"
)

// ImportError contains only fixed messages/codes, never untrusted URI values.
type ImportError struct{ Code string }

func (e *ImportError) Error() string {
	switch e.Code {
	case "UNSUPPORTED_TRANSPORT":
		return "Транспорт профиля пока не поддерживается. XHTTP не заменяется на TCP; используйте совместимый профиль TCP, WS, gRPC или HTTP."
	case "UNSUPPORTED_SECURITY":
		return "Неподдерживаемый режим защиты VLESS; допустимы none, tls и reality."
	case "UNSUPPORTED_FLOW":
		return "Неподдерживаемый flow VLESS или несовместимое сочетание flow, защиты и транспорта."
	case "UNSUPPORTED_PACKET_ENCODING":
		return "Неподдерживаемый формат UDP-пакетов VLESS."
	case "INSECURE_TLS":
		return "Импорт с отключённой проверкой сертификата запрещён. Нужен профиль с корректной проверкой TLS."
	default:
		return "Профиль содержит некорректные, неоднозначные или неподдерживаемые параметры."
	}
}

func importError(code string) error { return &ImportError{Code: code} }

// Source labels and other display fields are untrusted, too. Mask known
// credentials even when repeated outside their ordinary secret fields.
func redactPreview(preview Preview, outbound map[string]any) Preview {
	var secrets []string
	var collect func(map[string]any)
	collect = func(m map[string]any) {
		for k, v := range m {
			if nested, ok := v.(map[string]any); ok {
				collect(nested)
			}
			switch k {
			case "uuid", "password", "private_key", "public_key", "short_id":
				if s, ok := v.(string); ok && s != "" {
					secrets = append(secrets, s)
				}
			}
		}
	}
	collect(outbound)
	mask := func(s string) string {
		if strings.Contains(s, "://") {
			return "[скрыто]"
		}
		for _, secret := range secrets {
			s = strings.ReplaceAll(s, secret, "[скрыто]")
		}
		return s
	}
	preview.Name, preview.Server = mask(preview.Name), mask(preview.Server)
	return preview
}

// Duplicate JSON fields otherwise use last-wins semantics, hiding an
// unsupported transport/security behind a second value. Reject them before
// normalization, with a depth bound and no values in the error.
func validateJSONFields(data []byte) error {
	d := json.NewDecoder(strings.NewReader(string(data)))
	var value func(int) error
	value = func(depth int) error {
		if depth > 32 {
			return importError("INVALID_PARAMETERS")
		}
		t, err := d.Token()
		if err != nil {
			return importError("INVALID_PARAMETERS")
		}
		if delim, ok := t.(json.Delim); ok {
			switch delim {
			case '{':
				seen := map[string]bool{}
				for d.More() {
					key, err := d.Token()
					if err != nil {
						return importError("INVALID_PARAMETERS")
					}
					s, ok := key.(string)
					if !ok || seen[s] {
						return importError("INVALID_PARAMETERS")
					}
					seen[s] = true
					if err := value(depth + 1); err != nil {
						return err
					}
				}
			case '[':
				for d.More() {
					if err := value(depth + 1); err != nil {
						return err
					}
				}
			default:
				return importError("INVALID_PARAMETERS")
			}
			if _, err := d.Token(); err != nil {
				return importError("INVALID_PARAMETERS")
			}
		}
		return nil
	}
	return value(0)
}

func ErrorCode(err error) string {
	var typed *ImportError
	if errors.As(err, &typed) {
		return typed.Code
	}
	return "INVALID_PROFILE"
}

func validateVLESSModes(transport, security, flow, packet string) error {
	switch transport {
	case "tcp", "ws", "websocket", "grpc", "http", "h2":
	default:
		return importError("UNSUPPORTED_TRANSPORT")
	}
	switch security {
	case "none", "tls", "reality":
	default:
		return importError("UNSUPPORTED_SECURITY")
	}
	if flow != "" && (flow != "xtls-rprx-vision" || transport != "tcp" || security == "none") {
		return importError("UNSUPPORTED_FLOW")
	}
	switch packet {
	case "", "packetaddr", "xudp":
	default:
		return importError("UNSUPPORTED_PACKET_ENCODING")
	}
	return nil
}

// Reject ambiguous aliases and malformed query strings before url.Values.Get
// could silently choose one value or drop a malformed parameter.
func vlessQuery(u *url.URL) (url.Values, error) {
	q, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return nil, importError("INVALID_PARAMETERS")
	}
	aliases := map[string]string{"serverName": "sni", "publicKey": "pbk", "shortId": "sid", "fingerprint": "fp", "service_name": "serviceName", "packetEncoding": "packet_encoding", "allowInsecure": "insecure"}
	allowed := strings.Fields("security type flow packet_encoding sni pbk sid fp alpn path host serviceName insecure encryption headerType")
	clean := url.Values{}
	for key, values := range q {
		if len(values) != 1 {
			return nil, importError("INVALID_PARAMETERS")
		}
		if !utf8.ValidString(values[0]) || strings.IndexFunc(values[0], func(r rune) bool { return r < 32 || r == 127 }) >= 0 {
			return nil, importError("INVALID_PARAMETERS")
		}
		if alias, ok := aliases[key]; ok {
			key = alias
		}
		known := false
		for _, name := range allowed {
			known = known || key == name
		}
		if !known || clean.Has(key) {
			return nil, importError("INVALID_PARAMETERS")
		}
		clean.Set(key, strings.TrimSpace(values[0]))
	}
	for _, key := range []string{"encryption", "headerType"} {
		if clean.Has(key) && clean.Get(key) != "none" {
			return nil, importError("INVALID_PARAMETERS")
		}
	}
	if clean.Has("insecure") {
		switch strings.ToLower(clean.Get("insecure")) {
		case "0", "false", "no":
		case "1", "true", "yes":
			return nil, importError("INSECURE_TLS")
		default:
			return nil, importError("INVALID_PARAMETERS")
		}
	}
	return clean, nil
}

func validateClashVLESS(proxy map[string]any) error {
	transport, err := strictText(proxy, "network")
	if err != nil {
		return err
	}
	if transport == "" {
		transport = "tcp"
	}
	flow, err := strictText(proxy, "flow")
	if err != nil {
		return err
	}
	packet, err := strictText(proxy, "packet-encoding")
	if err != nil {
		return err
	}
	enabled, err := strictBool(proxy, "tls")
	if err != nil {
		return err
	}
	insecure, err := strictBool(proxy, "skip-cert-verify")
	if err != nil {
		return err
	}
	if insecure {
		return importError("INSECURE_TLS")
	}
	security := "none"
	if enabled {
		security = "tls"
	}
	if raw, exists := proxy["reality-opts"]; exists {
		r, ok := raw.(map[string]any)
		if !ok || stringField(r, "public-key") == "" {
			return importError("INVALID_PARAMETERS")
		}
		security = "reality"
	}
	// Only transports actually mapped by clashTransport are accepted here.
	if transport == "websocket" {
		return importError("UNSUPPORTED_TRANSPORT")
	}
	return validateVLESSModes(transport, security, flow, packet)
}

func strictText(m map[string]any, key string) (string, error) {
	v, exists := m[key]
	if !exists {
		return "", nil
	}
	s, ok := v.(string)
	if !ok {
		return "", importError("INVALID_PARAMETERS")
	}
	return strings.TrimSpace(s), nil
}

func strictBool(m map[string]any, key string) (bool, error) {
	v, exists := m[key]
	if !exists {
		return false, nil
	}
	b, ok := v.(bool)
	if !ok {
		return false, importError("INVALID_PARAMETERS")
	}
	return b, nil
}

func validateNativeVLESS(source map[string]any) error {
	flow, err := strictText(source, "flow")
	if err != nil {
		return err
	}
	packet, err := strictText(source, "packet_encoding")
	if err != nil {
		return err
	}
	transport, security := "tcp", "none"
	if raw, exists := source["transport"]; exists {
		m, ok := raw.(map[string]any)
		if !ok {
			return importError("INVALID_PARAMETERS")
		}
		transport, err = strictText(m, "type")
		if err != nil {
			return err
		}
		// Native TCP is represented by absence of transport, not type:tcp.
		if transport == "" || transport == "tcp" || transport == "websocket" || transport == "h2" {
			return importError("UNSUPPORTED_TRANSPORT")
		}
	}
	if raw, exists := source["tls"]; exists {
		m, ok := raw.(map[string]any)
		if !ok {
			return importError("INVALID_PARAMETERS")
		}
		enabled, err := strictBool(m, "enabled")
		if err != nil {
			return err
		}
		insecure, err := strictBool(m, "insecure")
		if err != nil {
			return err
		}
		if insecure {
			return importError("INSECURE_TLS")
		}
		if enabled {
			security = "tls"
		}
		if raw, exists := m["reality"]; exists {
			r, ok := raw.(map[string]any)
			if !ok {
				return importError("INVALID_PARAMETERS")
			}
			on, err := strictBool(r, "enabled")
			if err != nil {
				return err
			}
			if on {
				if !enabled || stringField(r, "public_key") == "" {
					return importError("INVALID_PARAMETERS")
				}
				security = "reality"
			}
		}
	}
	return validateVLESSModes(transport, security, flow, packet)
}
