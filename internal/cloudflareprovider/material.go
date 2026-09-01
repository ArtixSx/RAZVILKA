package cloudflareprovider

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
)

var (
	ErrAccountNotFound           = errors.New("Cloudflare account was not found")
	ErrTunnelMaterialUnavailable = errors.New("Cloudflare account has no locally owned tunnel material")
)

// TunnelMaterial is a short-lived, least-privilege view used by trusted
// internal transport builders. It deliberately excludes device credentials.
// Its backing byte slices are erased when WithTunnelMaterial returns.
type TunnelMaterial struct {
	privateKey    []byte
	peerPublicKey []byte
	addresses     []netip.Prefix
	endpoints     []netip.AddrPort
}

// PrivateKey returns an explicit caller-owned copy. Callers that retain it are
// responsible for erasing their copy after constructing an isolated candidate.
func (material TunnelMaterial) PrivateKey() []byte {
	return append([]byte(nil), material.privateKey...)
}

func (material TunnelMaterial) PeerPublicKey() []byte {
	return append([]byte(nil), material.peerPublicKey...)
}

func (material TunnelMaterial) Addresses() []netip.Prefix {
	return append([]netip.Prefix(nil), material.addresses...)
}

func (material TunnelMaterial) Endpoints() []netip.AddrPort {
	return append([]netip.AddrPort(nil), material.endpoints...)
}

func (TunnelMaterial) String() string   { return "[private Cloudflare tunnel material]" }
func (TunnelMaterial) GoString() string { return "[private Cloudflare tunnel material]" }
func (material TunnelMaterial) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, material.String())
}
func (TunnelMaterial) MarshalJSON() ([]byte, error) {
	return json.Marshal("[private Cloudflare tunnel material]")
}

func (material *TunnelMaterial) erase() {
	for index := range material.privateKey {
		material.privateKey[index] = 0
	}
	for index := range material.peerPublicKey {
		material.peerPublicKey[index] = 0
	}
	material.addresses = nil
	material.endpoints = nil
}

// WithTunnelMaterial grants a trusted internal callback the minimum secrets
// required to build an isolated WireGuard candidate. It does not expose account
// credentials, persist an export, start a process or change routes. Only a
// locally generated registration candidate is eligible.
func (s *Store) WithTunnelMaterial(ctx context.Context, accountID string, consume func(context.Context, TunnelMaterial) error) error {
	if consume == nil {
		return ErrTunnelMaterialUnavailable
	}
	s.mu.Lock()
	if err := ctx.Err(); err != nil {
		s.mu.Unlock()
		return err
	}
	doc, err := s.loadContext(ctx)
	if err != nil {
		s.mu.Unlock()
		return err
	}
	var raw []byte
	found := false
	for _, record := range doc.Accounts {
		if record.ID == accountID {
			found = true
			if record.Kind == SourceLocalRegistration {
				raw = append([]byte(nil), record.Raw...)
			}
			break
		}
	}
	s.mu.Unlock()
	if !found {
		return ErrAccountNotFound
	}
	if len(raw) == 0 {
		return ErrTunnelMaterialUnavailable
	}
	defer eraseBytes(raw)
	material, err := decodeTunnelMaterial(raw)
	if err != nil {
		return ErrStore
	}
	defer material.erase()
	if err := ctx.Err(); err != nil {
		return err
	}
	return consume(ctx, material)
}

func decodeTunnelMaterial(raw []byte) (TunnelMaterial, error) {
	if _, err := parseStoredImport(SourceLocalRegistration, raw); err != nil {
		return TunnelMaterial{}, err
	}
	fields, err := readJSONObject(raw)
	if err != nil {
		return TunnelMaterial{}, err
	}
	var privateText, peerText string
	var addressText, endpointText []string
	if json.Unmarshal(fields["private_key"], &privateText) != nil || json.Unmarshal(fields["peer_public_key"], &peerText) != nil ||
		json.Unmarshal(fields["addresses"], &addressText) != nil || json.Unmarshal(fields["endpoints"], &endpointText) != nil {
		return TunnelMaterial{}, ErrImport
	}
	privateKey, err := base64.StdEncoding.DecodeString(privateText)
	if err != nil || len(privateKey) != 32 {
		return TunnelMaterial{}, ErrImport
	}
	peerPublicKey, err := base64.StdEncoding.DecodeString(peerText)
	if err != nil || len(peerPublicKey) != 32 {
		eraseBytes(privateKey)
		return TunnelMaterial{}, ErrImport
	}
	material := TunnelMaterial{privateKey: privateKey, peerPublicKey: peerPublicKey}
	for _, value := range addressText {
		prefix, parseErr := netip.ParsePrefix(value)
		if parseErr != nil {
			material.erase()
			return TunnelMaterial{}, ErrImport
		}
		material.addresses = append(material.addresses, prefix)
	}
	for _, value := range endpointText {
		endpoint, parseErr := netip.ParseAddrPort(value)
		if parseErr != nil {
			material.erase()
			return TunnelMaterial{}, ErrImport
		}
		material.endpoints = append(material.endpoints, endpoint)
	}
	return material, nil
}

func eraseBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
