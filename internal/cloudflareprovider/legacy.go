package cloudflareprovider

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/netip"
	"strings"
)

// Typed adapters are pinned to the upstream schemas documented in
// docs/CLOUDFLARE_LEGACY_IMPORT_RU.md. They never contact either provider.
type usqueV1 struct {
	PrivateKey     string `json:"private_key"`
	EndpointV4     string `json:"endpoint_v4"`
	EndpointV6     string `json:"endpoint_v6"`
	EndpointH2V4   string `json:"endpoint_h2_v4"`
	EndpointH2V6   string `json:"endpoint_h2_v6"`
	EndpointPubKey string `json:"endpoint_pub_key"`
	ID             string `json:"id"`
	AccessToken    string `json:"access_token"`
	IPv4           string `json:"ipv4"`
	IPv6           string `json:"ipv6"`
}

// Return only derived non-secret facts. Future runtimes must revalidate the
// private bytes through this adapter; an opaque archive is not compatible.
type usqueFacts struct {
	fingerprint string
	addresses   []string
}

func parseUSQUEV1(data []byte) (usqueFacts, error) {
	fields, err := readJSONObject(data)
	if err != nil {
		return usqueFacts{}, err
	}
	known := map[string]bool{"private_key": true, "endpoint_v4": true, "endpoint_v6": true, "endpoint_h2_v4": true, "endpoint_h2_v6": true, "endpoint_pub_key": true, "id": true, "access_token": true, "ipv4": true, "ipv6": true}
	for name := range fields {
		if lower := strings.ToLower(name); lower != name && known[lower] {
			return usqueFacts{}, ErrImport
		}
	}
	var cfg usqueV1
	if json.Unmarshal(data, &cfg) != nil {
		return usqueFacts{}, ErrImport
	}
	der, err := base64.StdEncoding.DecodeString(cfg.PrivateKey)
	if err != nil {
		return usqueFacts{}, ErrImport
	}
	key, err := x509.ParseECPrivateKey(der)
	if err != nil || key.Curve != elliptic.P256() {
		return usqueFacts{}, ErrImport
	}
	public, rest := pem.Decode([]byte(cfg.EndpointPubKey))
	if public == nil || public.Type != "PUBLIC KEY" || len(public.Headers) != 0 || strings.TrimSpace(string(rest)) != "" {
		return usqueFacts{}, ErrImport
	}
	peer, err := x509.ParsePKIXPublicKey(public.Bytes)
	if err != nil {
		return usqueFacts{}, ErrImport
	}
	peerKey, ok := peer.(*ecdsa.PublicKey)
	if !ok || peerKey.Curve != elliptic.P256() {
		return usqueFacts{}, ErrImport
	}
	if !credential(cfg.ID) || !credential(cfg.AccessToken) {
		return usqueFacts{}, ErrImport
	}
	for _, endpoint := range []struct {
		value string
		v4    bool
	}{{cfg.EndpointV4, true}, {cfg.EndpointV6, false}, {cfg.EndpointH2V4, true}, {cfg.EndpointH2V6, false}} {
		if endpoint.value == "" {
			continue
		}
		ip, err := netip.ParseAddr(endpoint.value)
		if err != nil || ip.Zone() != "" || ip.Is4() != endpoint.v4 || !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.Is4In6() {
			return usqueFacts{}, ErrImport
		}
	}
	if cfg.EndpointV4 == "" && cfg.EndpointV6 == "" {
		return usqueFacts{}, ErrImport
	}
	var addresses []string
	for _, address := range []struct {
		value string
		v4    bool
	}{{cfg.IPv4, true}, {cfg.IPv6, false}} {
		if address.value == "" {
			continue
		}
		ip, err := netip.ParseAddr(address.value)
		if err != nil || ip.Zone() != "" || ip.Is4() != address.v4 || ip.Is4In6() || !ip.IsGlobalUnicast() || ip.IsLoopback() {
			return usqueFacts{}, ErrImport
		}
		addresses = append(addresses, ip.String())
	}
	if len(addresses) == 0 {
		return usqueFacts{}, ErrImport
	}
	pub, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return usqueFacts{}, ErrImport
	}
	return usqueFacts{fingerprint: digest(pub), addresses: addresses}, nil
}

func credential(value string) bool {
	if len(value) == 0 || len(value) > 16384 || strings.TrimSpace(value) != value {
		return false
	}
	for _, c := range value {
		if c < 33 || c > 126 {
			return false
		}
	}
	marker := strings.ToLower(strings.Trim(value, "[]<>*"))
	return marker != "" && marker != "redacted" && marker != "hidden"
}

func inspectWGCF(data []byte, view *Account) error {
	values := map[string]string{}
	allowed := map[string]bool{"private_key": true, "access_token": true, "device_id": true, "license_key": true}
	// wgcf serializes four flat string values. Intentionally accept only this
	// emitted TOML subset, not tables, escapes, multiline strings or coercions.
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		name, raw, ok := strings.Cut(line, "=")
		name, raw = strings.TrimSpace(name), strings.TrimSpace(raw)
		if !ok || !allowed[name] {
			return ErrImport
		}
		if _, exists := values[name]; exists {
			return ErrImport
		}
		if len(raw) < 2 || (raw[0] != '\'' && raw[0] != '"') {
			return ErrImport
		}
		end := strings.IndexByte(raw[1:], raw[0]) + 1
		if end < 1 {
			return ErrImport
		}
		value, suffix := raw[1:end], strings.TrimSpace(raw[end+1:])
		if strings.ContainsAny(value, "\\\r\n") || suffix != "" && !strings.HasPrefix(suffix, "#") {
			return ErrImport
		}
		if value != "" && !credential(value) {
			return ErrImport
		}
		values[name] = value
	}
	if !credential(values["device_id"]) || !credential(values["access_token"]) {
		return ErrImport
	}
	raw, err := wireGuardKey(values["private_key"])
	if err != nil {
		return err
	}
	key, err := ecdh.X25519().NewPrivateKey(raw)
	if err != nil {
		return ErrImport
	}
	view.Format, view.Transport = "wgcf-account-v1", "wireguard"
	view.PublicKeyFingerprint = digest(key.PublicKey().Bytes())
	view.HasPrivateKey, view.HasAccessToken, view.HasDeviceID = true, true, true
	view.HasLicense = values["license_key"] != ""
	return nil
}
