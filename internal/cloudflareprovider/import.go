package cloudflareprovider

import (
	"bytes"
	"crypto/ecdh"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

var ErrImport = errors.New("invalid or unsupported Cloudflare import; input values are hidden")

// ParseImport is passive: source bytes come from the caller, not a filesystem
// path or URL. It does not attest that the imported profile belongs to Cloudflare.
func ParseImport(kind string, data []byte) (Import, error) {
	if len(data) == 0 || len(data) > MaxImportBytes || !utf8.Valid(data) || bytes.IndexByte(data, 0) >= 0 {
		return Import{}, ErrImport
	}
	view := Account{Provider: "cloudflare", SourceKind: kind, Ownership: "copied-snapshot", Verification: "imported-unverified"}
	var err error
	switch kind {
	case SourceWireGuard:
		err = inspectWireGuard(data, &view)
	case SourceUSQUE:
		err = inspectUSQUE(data, &view)
	default:
		err = ErrImport
	}
	if err != nil {
		return Import{}, ErrImport
	}
	return Import{kind: kind, raw: append([]byte(nil), data...), preview: view}, nil
}

// This importer deliberately rejects hooks, duplicate fields/sections and
// unknown extensions. AWG compatibility and wgcf account TOML are separate work.
func inspectWireGuard(data []byte, view *Account) error {
	allowed := map[string]bool{
		"Interface.PrivateKey": true, "Interface.Address": true, "Interface.DNS": true, "Interface.MTU": true,
		"Peer.PublicKey": true, "Peer.PresharedKey": true, "Peer.AllowedIPs": true, "Peer.Endpoint": true, "Peer.PersistentKeepalive": true,
	}
	fields, sections := map[string]string{}, map[string]bool{}
	section := ""
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.TrimSpace(line[1 : len(line)-1])
			if (section != "Interface" && section != "Peer") || sections[section] {
				return ErrImport
			}
			sections[section] = true
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		key = section + "." + strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if !ok || !allowed[key] || fields[key] != "" || value == "" {
			return ErrImport
		}
		fields[key] = value
	}
	private, err := wireGuardKey(fields["Interface.PrivateKey"])
	if err != nil {
		return err
	}
	if _, err := wireGuardKey(fields["Peer.PublicKey"]); err != nil {
		return err
	}
	if value := fields["Peer.PresharedKey"]; value != "" {
		if _, err := wireGuardKey(value); err != nil {
			return err
		}
	}
	key, err := ecdh.X25519().NewPrivateKey(private)
	if err != nil {
		return err
	}
	view.HasPrivateKey = true
	view.PublicKeyFingerprint = digest(key.PublicKey().Bytes())
	view.AssignedAddresses, err = prefixes(fields["Interface.Address"])
	if err != nil {
		return err
	}
	if _, err := prefixes(fields["Peer.AllowedIPs"]); err != nil {
		return err
	}
	host, port, err := net.SplitHostPort(fields["Peer.Endpoint"])
	if err != nil || host == "" || strings.ContainsAny(host, " /\\@?#\t\r\n") {
		return ErrImport
	}
	if p, err := strconv.Atoi(port); err != nil || p < 1 || p > 65535 {
		return ErrImport
	}
	if value := fields["Interface.MTU"]; value != "" {
		if mtu, err := strconv.Atoi(value); err != nil || mtu < 576 || mtu > 9000 {
			return ErrImport
		}
	}
	if value := fields["Peer.PersistentKeepalive"]; value != "" {
		if interval, err := strconv.Atoi(value); err != nil || interval < 0 || interval > 65535 {
			return ErrImport
		}
	}
	return nil
}

func wireGuardKey(value string) ([]byte, error) {
	key, err := base64.StdEncoding.DecodeString(value)
	if err != nil || len(key) != 32 || bytes.Equal(key, make([]byte, 32)) {
		return nil, ErrImport
	}
	return key, nil
}

func prefixes(value string) ([]string, error) {
	items := strings.Split(value, ",")
	if value == "" || len(items) > 32 {
		return nil, ErrImport
	}
	seen := map[string]bool{}
	var out []string
	for _, raw := range items {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(raw))
		if err != nil {
			return nil, ErrImport
		}
		canonical := prefix.String()
		if !seen[canonical] {
			out = append(out, canonical)
			seen[canonical] = true
		}
	}
	sort.Strings(out)
	return out, nil
}

func inspectUSQUE(data []byte, view *Account) error {
	// Preserve unknown compatibility fields only as private inert bytes. Reject
	// ambiguous duplicate top-level keys instead of applying JSON last-wins.
	d := json.NewDecoder(bytes.NewReader(data))
	start, err := d.Token()
	if err != nil || start != json.Delim('{') {
		return ErrImport
	}
	fields := map[string]json.RawMessage{}
	for d.More() {
		token, err := d.Token()
		key, ok := token.(string)
		if err != nil || !ok || len(fields) >= 128 {
			return ErrImport
		}
		if _, exists := fields[key]; exists {
			return ErrImport
		}
		var value json.RawMessage
		if d.Decode(&value) != nil {
			return ErrImport
		}
		fields[key] = value
	}
	if _, err := d.Token(); err != nil {
		return ErrImport
	}
	if _, err := d.Token(); !errors.Is(err, io.EOF) {
		return ErrImport
	}
	for _, name := range []string{"private_key", "endpoint_pub_key", "id", "access_token"} {
		var value string
		if json.Unmarshal(fields[name], &value) != nil || len(value) > 16384 {
			return ErrImport
		}
		value = strings.TrimSpace(value)
		marker := strings.ToLower(strings.Trim(value, "[]<>*"))
		if value == "" || marker == "" || marker == "redacted" || marker == "hidden" {
			return ErrImport
		}
	}
	// Key encoding/API versions vary between USQUE builds. Parsing is not key
	// validation or registration proof; leave fingerprints/addresses unknown.
	view.HasPrivateKey, view.HasAccessToken, view.HasDeviceID = true, true, true
	return nil
}
