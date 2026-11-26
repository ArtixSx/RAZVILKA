package providerprofile

// ValidateXrayXHTTPSettings is the same restricted, pinned transport contract
// used by the compiler. Scoped adapters can use it when validating trusted
// compiler material; it does not authorize imported routing or endpoints.
func ValidateXrayXHTTPSettings(settings map[string]any) error {
	if settings == nil {
		return errXrayProfile
	}
	if _, exists := settings["type"]; exists {
		return errXrayProfile
	}
	m := make(map[string]any, len(settings)+1)
	for field, value := range settings {
		m[field] = value
	}
	m["type"] = "xhttp"
	return validateXHTTPTransport(m)
}

// Only the single XHTTP VLESS exit of an Xray JSON source is projected into
// canonical node material. Unknown auth/security/socket fields fail closed.
func normalizeXrayXHTTPOutbound(source map[string]any) (map[string]any, Preview, error) {
	bad := importError("INVALID_PARAMETERS")
	if onlyProfileFields(source, "protocol tag settings streamSettings") != nil || source["protocol"] != "vless" {
		return nil, Preview{}, bad
	}
	settings, ok := source["settings"].(map[string]any)
	if !ok || onlyProfileFields(settings, "vnext") != nil {
		return nil, Preview{}, bad
	}
	servers, ok := settings["vnext"].([]any)
	if !ok || len(servers) != 1 {
		return nil, Preview{}, bad
	}
	server, ok := servers[0].(map[string]any)
	if !ok || onlyProfileFields(server, "address port users") != nil {
		return nil, Preview{}, bad
	}
	users, ok := server["users"].([]any)
	if !ok || len(users) != 1 {
		return nil, Preview{}, bad
	}
	user, ok := users[0].(map[string]any)
	if !ok || onlyProfileFields(user, "id encryption flow") != nil || user["encryption"] != "none" {
		return nil, Preview{}, bad
	}
	if _, err := strictText(user, "flow"); err != nil {
		return nil, Preview{}, bad
	}
	stream, ok := source["streamSettings"].(map[string]any)
	if !ok || onlyProfileFields(stream, "network security tlsSettings realitySettings xhttpSettings splithttpSettings") != nil {
		return nil, Preview{}, bad
	}
	network, _ := stream["network"].(string)
	key := "xhttpSettings"
	if network == "splithttp" {
		key = "splithttpSettings"
	} else if network != "xhttp" {
		return nil, Preview{}, importError("UNSUPPORTED_TRANSPORT")
	}
	if _, exists := stream["xhttpSettings"]; exists && key != "xhttpSettings" {
		return nil, Preview{}, bad
	}
	if _, exists := stream["splithttpSettings"]; exists && key != "splithttpSettings" {
		return nil, Preview{}, bad
	}
	xsettings, ok := stream[key].(map[string]any)
	if !ok || onlyProfileFields(xsettings, "host path mode extra "+xhttpExtraFields) != nil {
		return nil, Preview{}, bad
	}
	transport := map[string]any{"type": "xhttp"}
	for _, field := range []string{"host", "path", "mode"} {
		if value, exists := xsettings[field]; exists {
			if !xhttpText(value) {
				return nil, Preview{}, bad
			}
			transport[field] = value
		}
	}
	// With extra present upstream ignores all non-core top-level options.
	// Reject that ambiguity rather than losing the caller's settings.
	extra, hasExtra := xsettings["extra"]
	topExtra := map[string]any{}
	for field, value := range xsettings {
		if field != "host" && field != "path" && field != "mode" && field != "extra" {
			topExtra[field] = value
		}
	}
	if hasExtra {
		if len(topExtra) != 0 {
			return nil, Preview{}, bad
		}
		transport["extra"] = extra
	} else if len(topExtra) > 0 {
		transport["extra"] = topExtra
	}
	if validateXHTTPTransport(transport) != nil {
		return nil, Preview{}, bad
	}
	tls := map[string]any{"enabled": true}
	switch stream["security"] {
	case "tls":
		if _, exists := stream["realitySettings"]; exists {
			return nil, Preview{}, bad
		}
		options, ok := stream["tlsSettings"].(map[string]any)
		if !ok || onlyProfileFields(options, "serverName fingerprint alpn allowInsecure") != nil {
			return nil, Preview{}, bad
		}
		if value, exists := options["alpn"]; exists {
			tls["alpn"] = value
		}
		if value, exists := options["allowInsecure"]; exists {
			tls["insecure"] = value
		}
		if value, exists := options["serverName"]; exists {
			tls["server_name"] = value
		}
		if value, exists := options["fingerprint"]; exists {
			tls["utls"] = map[string]any{"enabled": true, "fingerprint": value}
		}
	case "reality":
		if _, exists := stream["tlsSettings"]; exists {
			return nil, Preview{}, bad
		}
		options, ok := stream["realitySettings"].(map[string]any)
		if !ok || onlyProfileFields(options, "serverName fingerprint publicKey password shortId") != nil {
			return nil, Preview{}, bad
		}
		publicKey := options["publicKey"]
		if password, exists := options["password"]; exists {
			if _, duplicate := options["publicKey"]; duplicate {
				return nil, Preview{}, bad
			}
			publicKey = password
		}
		tls["server_name"] = options["serverName"]
		if value, exists := options["fingerprint"]; exists {
			tls["utls"] = map[string]any{"enabled": true, "fingerprint": value}
		}
		reality := map[string]any{"enabled": true, "public_key": publicKey}
		if value, exists := options["shortId"]; exists {
			reality["short_id"] = value
		}
		tls["reality"] = reality
	default:
		return nil, Preview{}, importError("UNSUPPORTED_SECURITY")
	}
	out := map[string]any{"type": "vless", "server": server["address"], "server_port": server["port"], "uuid": user["id"], "tls": tls, "transport": transport}
	copyFields(out, source, "tag")
	copyFields(out, user, "flow")
	return normalizeNativeOutbound(out)
}
