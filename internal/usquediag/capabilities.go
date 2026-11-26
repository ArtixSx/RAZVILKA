package usquediag

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/netip"
	"time"

	"github.com/ArtixSx/razvilka/internal/publicfetch"
)

// Capability evidence expires at most five minutes after the native canary.
// The receipt is diagnostic only; it never authorizes Apply or enrollment.
const MaxCanaryAge = 5 * time.Minute

type TransportCapabilities struct {
	HTTP2      string `json:"http2"`
	HTTP3      string `json:"http3"`
	UDP        string `json:"udp"`
	Fresh      bool   `json:"fresh"`
	ReasonCode string `json:"reason_code"`
}

func unknownCapabilities(reason string) TransportCapabilities {
	return TransportCapabilities{HTTP2: "unknown", HTTP3: "unknown", UDP: "unknown", ReasonCode: reason}
}

func canaryDigest(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == 32 && hex.EncodeToString(decoded) == value
}

// CanaryBinding binds the exact config/session/binary bytes and the trusted
// current network/boot epoch, without exposing any private material. A caller
// must never derive environmentID from the receipt itself or a UI request.
func CanaryBinding(configSHA, sessionSHA, binarySHA, environmentID string) string {
	for _, digest := range []string{configSHA, sessionSHA, binarySHA, environmentID} {
		if !canaryDigest(digest) {
			return ""
		}
	}
	data, _ := json.Marshal([]string{"usque-canary-binding-v1", configSHA, sessionSHA, binarySHA, environmentID})
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// EvaluateCanaryCapabilities accepts only a trusted native canary receipt for
// one exact transport and pinned endpoint in the current environment. Success
// on HTTP/2 says nothing about UDP/HTTP3; QUIC says nothing about HTTP/2. A
// missing proof is unknown, never evidence that the other transport failed.
func EvaluateCanaryCapabilities(receipt CanaryEvidence, endpoints Endpoints, binding string, now time.Time) TransportCapabilities {
	result := unknownCapabilities("receipt-unbound")
	if !canaryDigest(binding) || receipt.BindingID != binding {
		return result
	}
	checked, err := time.Parse(time.RFC3339, receipt.CheckedAt)
	until, expiryErr := time.Parse(time.RFC3339, receipt.ValidUntil)
	if err != nil || expiryErr != nil || checked.After(now) || !until.After(checked) || until.Sub(checked) > MaxCanaryAge || !now.Before(until) {
		return unknownCapabilities("receipt-stale-or-invalid")
	}
	addresses := []string{}
	switch receipt.Transport {
	case "HTTP/2":
		addresses = []string{endpoints.H2IPv4, endpoints.H2IPv6}
	case "QUIC":
		addresses = []string{endpoints.IPv4, endpoints.IPv6}
	default:
		return unknownCapabilities("transport-unconfirmed")
	}
	matched := false
	endpoint, endpointErr := netip.ParseAddrPort(receipt.Endpoint)
	if endpointErr != nil || endpoint.Port() != 443 || endpoint.Addr().Is4In6() || !publicfetch.PublicAddress(endpoint.Addr()) || endpoint.String() != receipt.Endpoint {
		return unknownCapabilities("endpoint-changed-or-unconfirmed")
	}
	for _, raw := range addresses {
		address, err := netip.ParseAddr(raw)
		if err == nil && raw != "" && netip.AddrPortFrom(address, 443).String() == receipt.Endpoint {
			matched = true
		}
	}
	if !matched {
		return unknownCapabilities("endpoint-changed-or-unconfirmed")
	}
	if receipt.Warp != "on" && receipt.Warp != "plus" {
		return unknownCapabilities("warp-unconfirmed")
	}
	result.Fresh, result.ReasonCode = true, "native-canary-confirmed"
	if receipt.Transport == "HTTP/2" {
		result.HTTP2 = "confirmed"
	} else {
		result.HTTP3, result.UDP = "confirmed", "confirmed"
	}
	return result
}
