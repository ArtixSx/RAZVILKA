package providerprofile

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// VLESSProfile is the engine-neutral form of one VLESS connection. The share
// link, subscription and JSON parsers validate the source first; every engine
// compiler then declares the subset it supports. A required field outside
// that subset is rejected, never dropped.
type VLESSProfile struct {
	Server           string
	Port             int
	UUID             string
	Flow             string
	Security         string // none, tls or reality
	Transport        string // tcp (Xray RAW), ws, grpc or http
	ServerName       string
	Fingerprint      string
	ALPN             []string
	Insecure         bool
	RealityPublicKey string
	RealityShortID   string
	Path             string
	Host             string
	ServiceName      string
	PacketEncoding   string
}

// XrayResult is a draft for the managed Xray engine: one outbound, no
// inbounds, routing, DNS, API or other control surfaces from the source.
type XrayResult struct {
	Preview BundlePreview
	Config  []byte
}

var errXrayProfile = importError("XRAY_UNSUPPORTED_PROFILE")

// ParseXrayProfile selects one VLESS node from a share link, subscription or
// profile and compiles it for Xray. Xray uses exactly one remote exit here;
// the rest of a subscription stays available through Sing-box and NodeStore.
func ParseXrayProfile(raw string, selectedIndex int) (XrayResult, error) {
	bundle, err := ParseProfileWithSelection(raw, selectedIndex)
	if err != nil {
		return XrayResult{Preview: bundle.Preview}, err
	}
	outbound, err := selectedBundleOutbound(bundle.Config, selectedIndex, len(bundle.Preview.Nodes))
	if err != nil {
		return XrayResult{Preview: bundle.Preview}, err
	}
	profile, err := VLESSProfileFromOutbound(outbound)
	if err != nil {
		return XrayResult{Preview: bundle.Preview}, err
	}
	config, warnings, err := CompileXrayConfig(profile)
	if err != nil {
		return XrayResult{Preview: bundle.Preview}, err
	}
	preview := bundle.Preview
	preview.EngineID = "xray"
	preview.Warnings = append(slicesWithoutPoolNote(preview.Warnings), warnings...)
	if len(bundle.Preview.Nodes) > 1 {
		preview.Warnings = append(preview.Warnings, "Xray использует один выбранный узел. Остальные узлы подписки остаются доступны через Sing-box.")
	}
	return XrayResult{Preview: preview, Config: config}, nil
}

func slicesWithoutPoolNote(warnings []string) []string {
	out := make([]string, 0, len(warnings))
	for _, warning := range warnings {
		if !strings.HasPrefix(warning, "Sing-box локально проверит пул узлов") {
			out = append(out, warning)
		}
	}
	return out
}

func selectedBundleOutbound(config []byte, selectedIndex, nodes int) (map[string]any, error) {
	var document struct {
		Outbounds []map[string]any `json:"outbounds"`
	}
	if json.Unmarshal(config, &document) != nil {
		return nil, errors.New("не удалось прочитать разобранный профиль")
	}
	tag := "proxy"
	if nodes > 1 {
		tag = fmt.Sprintf("node-%02d", selectedIndex+1)
	}
	for _, outbound := range document.Outbounds {
		if outbound["tag"] == tag {
			return outbound, nil
		}
	}
	return nil, errors.New("выбранный узел отсутствует в профиле")
}

// VLESSProfileFromOutbound reads a VLESS outbound already rebuilt by this
// package's strict parsers. Any other protocol is not a VLESS profile.
func VLESSProfileFromOutbound(out map[string]any) (VLESSProfile, error) {
	text := func(m map[string]any, key string) string {
		value, _ := m[key].(string)
		return value
	}
	object := func(m map[string]any, key string) map[string]any {
		value, _ := m[key].(map[string]any)
		return value
	}
	if text(out, "type") != "vless" {
		return VLESSProfile{}, errXrayProfile
	}
	port, ok := jsonPort(out["server_port"])
	if !ok {
		return VLESSProfile{}, errXrayProfile
	}
	p := VLESSProfile{Server: text(out, "server"), Port: port, UUID: text(out, "uuid"), Flow: text(out, "flow"), PacketEncoding: text(out, "packet_encoding"), Security: "none", Transport: "tcp"}
	if tls := object(out, "tls"); tls != nil {
		p.Security = "tls"
		p.ServerName = text(tls, "server_name")
		p.Insecure, _ = tls["insecure"].(bool)
		p.ALPN = stringList(tls["alpn"])
		if utls := object(tls, "utls"); utls != nil {
			p.Fingerprint = text(utls, "fingerprint")
		}
		if reality := object(tls, "reality"); reality != nil {
			p.Security = "reality"
			p.RealityPublicKey = text(reality, "public_key")
			p.RealityShortID = text(reality, "short_id")
		}
	}
	if transport := object(out, "transport"); transport != nil {
		p.Transport = text(transport, "type")
		p.Path = text(transport, "path")
		p.ServiceName = text(transport, "service_name")
		if headers := object(transport, "headers"); headers != nil {
			p.Host = text(headers, "Host")
		}
		if hosts := stringList(transport["host"]); len(hosts) > 0 {
			p.Host = strings.Join(hosts, ",")
		}
	}
	if p.Server == "" || !looksLikeUUID(p.UUID) {
		return VLESSProfile{}, errXrayProfile
	}
	return p, nil
}

// CompileXrayConfig supports VLESS + REALITY or TLS over RAW/TCP, with the
// optional xtls-rprx-vision flow. Other transports are separate, later sets.
// The managed engine adds its own loopback inbound and log settings; the only
// outbound is the remote exit, so no imported DIRECT can become the default.
func CompileXrayConfig(p VLESSProfile) ([]byte, []string, error) {
	if p.Transport != "tcp" || p.Security != "reality" && p.Security != "tls" || p.Insecure {
		return nil, nil, errXrayProfile
	}
	if p.Flow != "" && p.Flow != "xtls-rprx-vision" || p.PacketEncoding != "" && p.PacketEncoding != "xudp" {
		return nil, nil, errXrayProfile
	}
	if p.Server == "" || p.Port < 1 || p.Port > 65535 || !looksLikeUUID(p.UUID) || p.ServerName == "" {
		return nil, nil, errXrayProfile
	}
	var warnings []string
	user := map[string]any{"id": p.UUID, "encryption": "none"}
	if p.Flow != "" {
		user["flow"] = p.Flow
	}
	stream := map[string]any{"network": "tcp", "security": p.Security}
	fingerprint := p.Fingerprint
	switch p.Security {
	case "reality":
		if p.RealityPublicKey == "" {
			return nil, nil, errXrayProfile
		}
		if fingerprint == "" {
			// REALITY needs a uTLS fingerprint; share links commonly omit it.
			fingerprint = "chrome"
			warnings = append(warnings, "В профиле не указан отпечаток TLS; для REALITY использован chrome.")
		}
		reality := map[string]any{"serverName": p.ServerName, "fingerprint": fingerprint, "publicKey": p.RealityPublicKey}
		if p.RealityShortID != "" {
			reality["shortId"] = p.RealityShortID
		}
		stream["realitySettings"] = reality
	case "tls":
		tls := map[string]any{"serverName": p.ServerName}
		if fingerprint != "" {
			tls["fingerprint"] = fingerprint
		}
		if len(p.ALPN) > 0 {
			tls["alpn"] = p.ALPN
		}
		stream["tlsSettings"] = tls
	}
	outbound := map[string]any{
		"tag": "proxy", "protocol": "vless",
		"settings":       map[string]any{"vnext": []any{map[string]any{"address": p.Server, "port": p.Port, "users": []any{user}}}},
		"streamSettings": stream,
	}
	document := map[string]any{
		"log":       map[string]any{"loglevel": "warning", "access": "none"},
		"outbounds": []any{outbound},
	}
	config, err := json.MarshalIndent(document, "", "  ")
	return config, warnings, err
}

func jsonPort(value any) (int, bool) {
	switch number := value.(type) {
	case float64:
		if number == float64(int(number)) {
			return int(number), number >= 1 && number <= 65535
		}
	case int:
		return number, number >= 1 && number <= 65535
	}
	return 0, false
}
