package cloudflareprovider

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
)

var (
	ErrCandidateInvalid = errors.New("Cloudflare WireGuard candidate options are invalid")
	ErrCandidateExpired = errors.New("Cloudflare WireGuard candidate secret lease has expired")
)

const (
	defaultCandidateMTU       = 1280
	defaultCandidateKeepalive = 25
)

// CandidateOptions only selects among server-issued endpoints and bounded
// interface values. AllowedIPs stay fixed to a full tunnel inside the future
// isolated probe; DNS and shell hooks are intentionally unsupported.
type CandidateOptions struct {
	EndpointIndex       int
	MTU                 int
	PersistentKeepalive int
}

type CandidatePreview struct {
	AccountID           string   `json:"account_id"`
	Transport           string   `json:"transport"`
	RoutePathID         string   `json:"route_path_id"`
	Endpoint            string   `json:"endpoint"`
	Addresses           []string `json:"addresses"`
	AllowedIPs          []string `json:"allowed_ips"`
	MTU                 int      `json:"mtu"`
	PersistentKeepalive int      `json:"persistent_keepalive"`
	Verification        string   `json:"verification"`
	valid               bool
}

// WireGuardCandidate exists only for the duration of WithWireGuardCandidate.
// It is an inert configuration image: constructing it never creates an
// interface, process, route, firewall rule or DNS change.
type WireGuardCandidate struct {
	preview       CandidatePreview
	privateKey    []byte
	peerPublicKey []byte
}

func (candidate WireGuardCandidate) Public() CandidatePreview {
	view := candidate.preview
	view.Addresses = append([]string(nil), view.Addresses...)
	view.AllowedIPs = append([]string(nil), view.AllowedIPs...)
	return view
}

func (candidate WireGuardCandidate) String() string {
	return "[private Cloudflare WireGuard candidate]"
}
func (candidate WireGuardCandidate) GoString() string {
	return "[private Cloudflare WireGuard candidate]"
}
func (candidate WireGuardCandidate) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, candidate.String())
}
func (candidate WireGuardCandidate) MarshalJSON() ([]byte, error) {
	return json.Marshal(candidate.Public())
}

// WriteConfig is an explicit secret export for a trusted isolated runner. The
// temporary serialization buffer is erased before returning. Callers own and
// must protect any bytes already accepted by writer.
func (candidate WireGuardCandidate) WriteConfig(writer io.Writer) error {
	if writer == nil || !validCandidateKey(candidate.privateKey) || !validCandidateKey(candidate.peerPublicKey) {
		return ErrCandidateExpired
	}
	var config bytes.Buffer
	config.WriteString("[Interface]\nPrivateKey = ")
	encodedKey := base64.StdEncoding.AppendEncode(nil, candidate.privateKey)
	config.Write(encodedKey)
	eraseBytes(encodedKey)
	config.WriteString("\nAddress = ")
	config.WriteString(strings.Join(candidate.preview.Addresses, ", "))
	config.WriteString("\nMTU = ")
	config.WriteString(strconv.Itoa(candidate.preview.MTU))
	config.WriteString("\n\n[Peer]\nPublicKey = ")
	encodedKey = base64.StdEncoding.AppendEncode(nil, candidate.peerPublicKey)
	config.Write(encodedKey)
	eraseBytes(encodedKey)
	config.WriteString("\nAllowedIPs = ")
	config.WriteString(strings.Join(candidate.preview.AllowedIPs, ", "))
	config.WriteString("\nEndpoint = ")
	config.WriteString(candidate.preview.Endpoint)
	config.WriteString("\nPersistentKeepalive = ")
	config.WriteString(strconv.Itoa(candidate.preview.PersistentKeepalive))
	config.WriteByte('\n')
	serialized := config.Bytes()
	defer eraseBytes(serialized)
	written, err := writer.Write(serialized)
	if err == nil && written != len(serialized) {
		return io.ErrShortWrite
	}
	return err
}

func (candidate *WireGuardCandidate) erase() {
	eraseBytes(candidate.privateKey)
	eraseBytes(candidate.peerPublicKey)
	candidate.preview.Addresses = nil
	candidate.preview.AllowedIPs = nil
}

func validCandidateKey(value []byte) bool {
	if len(value) != 32 {
		return false
	}
	for _, item := range value {
		if item != 0 {
			return true
		}
	}
	return false
}

func normalizeCandidateOptions(options CandidateOptions, endpointCount int) (CandidateOptions, error) {
	if options.MTU == 0 {
		options.MTU = defaultCandidateMTU
	}
	if options.PersistentKeepalive == 0 {
		options.PersistentKeepalive = defaultCandidateKeepalive
	}
	if options.EndpointIndex < 0 || options.EndpointIndex >= endpointCount || options.MTU < 576 || options.MTU > 1500 || options.PersistentKeepalive < 1 || options.PersistentKeepalive > 120 {
		return CandidateOptions{}, ErrCandidateInvalid
	}
	return options, nil
}

// WithWireGuardCandidate builds a deterministic, short-lived candidate from a
// locally owned account. The callback is responsible for using it only inside
// a separately isolated and bounded probe.
func (s *Store) WithWireGuardCandidate(ctx context.Context, accountID string, options CandidateOptions, consume func(context.Context, WireGuardCandidate) error) error {
	if consume == nil {
		return ErrCandidateInvalid
	}
	return s.WithTunnelMaterial(ctx, accountID, func(ctx context.Context, material TunnelMaterial) error {
		normalized, err := normalizeCandidateOptions(options, len(material.endpoints))
		if err != nil {
			return err
		}
		addresses := make([]string, 0, len(material.addresses))
		for _, address := range material.addresses {
			addresses = append(addresses, address.String())
		}
		candidate := WireGuardCandidate{
			preview: CandidatePreview{
				AccountID: accountID, Transport: "wireguard", Endpoint: material.endpoints[normalized.EndpointIndex].String(),
				Addresses: addresses, AllowedIPs: []string{"0.0.0.0/0", "::/0"}, MTU: normalized.MTU,
				PersistentKeepalive: normalized.PersistentKeepalive, Verification: "built-unverified", valid: true,
			},
			privateKey: material.PrivateKey(), peerPublicKey: material.PeerPublicKey(),
		}
		candidate.preview.RoutePathID = candidateRoutePathID(candidate.preview)
		defer candidate.erase()
		if err := ctx.Err(); err != nil {
			return err
		}
		return consume(ctx, candidate)
	})
}

func candidateRoutePathID(candidate CandidatePreview) string {
	identity := strings.Join([]string{
		candidate.AccountID, candidate.Transport, candidate.Endpoint,
		strings.Join(candidate.Addresses, ","), strings.Join(candidate.AllowedIPs, ","),
		strconv.Itoa(candidate.MTU), strconv.Itoa(candidate.PersistentKeepalive),
	}, "\x00")
	return "cloudflare-wg:" + digest([]byte(identity))
}
