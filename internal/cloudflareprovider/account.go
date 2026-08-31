// Package cloudflareprovider owns passive imported account snapshots.
// It performs no registration, network requests, runtime starts or route changes.
package cloudflareprovider

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"time"
)

const (
	Schema          = 1
	MaxImportBytes  = 256 << 10
	MaxAccounts     = 32
	SourceWireGuard = "wireguard-profile"
	SourceUSQUE     = "usque-session"
	SourceWGCF      = "wgcf-account"
)

// Account is deliberately separate from the private store document. IDs below
// belong to RAZVILKA, not Cloudflare. Import never proves registration or egress.
type Account struct {
	ID                   string    `json:"id"`
	Provider             string    `json:"provider"`
	SourceKind           string    `json:"source_kind"`
	Ownership            string    `json:"ownership"`
	Verification         string    `json:"verification"`
	SecretReference      string    `json:"secret_reference"`
	HasPrivateKey        bool      `json:"has_private_key"`
	HasAccessToken       bool      `json:"has_access_token"`
	HasDeviceID          bool      `json:"has_device_id"`
	Format               string    `json:"format"`
	Transport            string    `json:"transport,omitempty"`
	HasLicense           bool      `json:"has_license"`
	PublicKeyFingerprint string    `json:"public_key_fingerprint,omitempty"`
	AssignedAddresses    []string  `json:"assigned_addresses,omitempty"`
	CreatedAt            time.Time `json:"created_at"`
	UpdatedAt            time.Time `json:"updated_at"`
}

// Import holds private input without exposing it to JSON or formatted logs.
// Only the store may persist the raw snapshot. A future exporter must rebuild a
// transport-specific candidate, not execute the stored input verbatim.
type Import struct {
	kind    string
	raw     []byte
	preview Account
}

func (i Import) Preview() Account {
	view := i.preview
	view.AssignedAddresses = append([]string(nil), view.AssignedAddresses...)
	return view
}

func (i Import) MarshalJSON() ([]byte, error) { return json.Marshal(i.Preview()) }
func (i Import) String() string               { return "[private Cloudflare import]" }
func (i Import) Format(s fmt.State, _ rune)   { _, _ = io.WriteString(s, i.String()) }

func digest(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
