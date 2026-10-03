package providerprofile

import "strings"

// Unknown connection fields may describe authentication, certificate pins,
// chaining or transport. They must not disappear during normalization.
func onlyProfileFields(object map[string]any, fields string) error {
	allowed := strings.Fields(fields)
	for key := range object {
		found := false
		for _, name := range allowed {
			found = found || name == key
		}
		if !found {
			return importError("INVALID_PARAMETERS")
		}
	}
	return nil
}

func strictStringList(value any) ([]string, error) {
	var list []string
	switch items := value.(type) {
	case []string:
		list = append(list, items...)
	case []any:
		for _, item := range items {
			text, ok := item.(string)
			if !ok {
				return nil, importError("INVALID_PARAMETERS")
			}
			list = append(list, text)
		}
	default:
		return nil, importError("INVALID_PARAMETERS")
	}
	for _, item := range list {
		if strings.TrimSpace(item) == "" || strings.IndexFunc(item, func(r rune) bool { return r < 32 || r == 127 }) >= 0 {
			return nil, importError("INVALID_PARAMETERS")
		}
	}
	return list, nil
}

func validateVLESSFields(source map[string]any) error {
	if err := onlyProfileFields(source, "type tag server server_port uuid flow packet_encoding tls transport multiplex"); err != nil {
		return err
	}
	for _, key := range []string{"type", "server", "uuid", "flow", "packet_encoding"} {
		if _, err := strictText(source, key); err != nil {
			return err
		}
	}
	if raw, exists := source["tls"]; exists {
		tls, ok := raw.(map[string]any)
		if !ok || onlyProfileFields(tls, "enabled server_name insecure alpn min_version max_version cipher_suites utls reality") != nil {
			return importError("INVALID_PARAMETERS")
		}
		for _, key := range []string{"server_name", "min_version", "max_version"} {
			if _, err := strictText(tls, key); err != nil {
				return err
			}
		}
		for _, key := range []string{"alpn", "cipher_suites"} {
			if value, exists := tls[key]; exists {
				if _, err := strictStringList(value); err != nil {
					return err
				}
			}
		}
		for key, fields := range map[string]string{"utls": "enabled fingerprint", "reality": "enabled public_key short_id"} {
			if value, exists := tls[key]; exists {
				object, ok := value.(map[string]any)
				if !ok || onlyProfileFields(object, fields) != nil {
					return importError("INVALID_PARAMETERS")
				}
				if _, err := strictBool(object, "enabled"); err != nil {
					return err
				}
				for _, name := range strings.Fields(fields)[1:] {
					if _, err := strictText(object, name); err != nil {
						return err
					}
				}
			}
		}
	}
	return nil
}
