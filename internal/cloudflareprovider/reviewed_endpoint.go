package cloudflareprovider

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ArtixSx/razvilka/internal/publicfetch"
)

var ErrEndpointReview = errors.New("WireGuard endpoint review is unavailable, unsafe or expired")

const endpointReviewTTL = 2 * time.Minute
const maxEndpointReviewAddresses = 16

type EndpointResolver func(context.Context, string) ([]netip.Addr, error)

// WireGuardEndpointReview is an in-memory DNS preview. JSON is display-only:
// unexported binding/valid state prevents a restored or edited preview from
// authorizing a candidate.
type WireGuardEndpointReview struct {
	Host      string    `json:"host"`
	Port      uint16    `json:"port"`
	Addresses []string  `json:"addresses"`
	ExpiresAt time.Time `json:"expires_at"`

	profileBinding string
	original       string
	resolved       []string
	pinnedPort     uint16
	validUntil     time.Time
	valid          bool
}

func (review WireGuardEndpointReview) Public() WireGuardEndpointReview {
	review.Addresses = append([]string(nil), review.Addresses...)
	review.profileBinding = ""
	review.original = ""
	review.resolved = nil
	review.pinnedPort = 0
	review.validUntil = time.Time{}
	review.valid = false
	return review
}

func (review WireGuardEndpointReview) MarshalJSON() ([]byte, error) {
	type publicReview struct {
		Host      string    `json:"host"`
		Port      uint16    `json:"port"`
		Addresses []string  `json:"addresses"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	return json.Marshal(publicReview{Host: review.Host, Port: review.Port, Addresses: append([]string(nil), review.Addresses...), ExpiresAt: review.ExpiresAt})
}

func (WireGuardEndpointReview) String() string   { return "[reviewed WireGuard endpoint preview]" }
func (WireGuardEndpointReview) GoString() string { return "[reviewed WireGuard endpoint preview]" }
func (review WireGuardEndpointReview) Format(state fmt.State, _ rune) {
	_, _ = state.Write([]byte(review.String()))
}

// ReviewWireGuardEndpoint resolves once and rejects the whole answer set if it
// contains any private/reserved address. The later candidate pins one selected
// literal; DNS is never queried during interface creation.
func ReviewWireGuardEndpoint(ctx context.Context, profile []byte, resolver EndpointResolver) (WireGuardEndpointReview, error) {
	if ctx == nil {
		return WireGuardEndpointReview{}, ErrEndpointReview
	}
	parsed, err := ParseImport(SourceWireGuard, profile)
	if err != nil {
		return WireGuardEndpointReview{}, ErrEndpointReview
	}
	defer eraseBytes(parsed.raw)
	fields, err := wireGuardFields(profile)
	if err != nil {
		return WireGuardEndpointReview{}, ErrEndpointReview
	}
	host, portText, err := net.SplitHostPort(fields["Peer.Endpoint"])
	portValue, portErr := strconv.ParseUint(portText, 10, 16)
	if err != nil || portErr != nil || portValue == 0 {
		return WireGuardEndpointReview{}, ErrEndpointReview
	}
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	addresses := []netip.Addr{}
	if literal, parseErr := netip.ParseAddr(host); parseErr == nil {
		addresses = append(addresses, literal)
	} else {
		if resolver == nil || publicfetch.ValidateURL("https://"+host) != nil {
			return WireGuardEndpointReview{}, ErrEndpointReview
		}
		resolveCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
		addresses, err = resolver(resolveCtx, host)
		resolveErr := resolveCtx.Err()
		cancel()
		if resolveErr != nil {
			return WireGuardEndpointReview{}, resolveErr
		}
		if err != nil {
			return WireGuardEndpointReview{}, ErrEndpointReview
		}
	}
	if len(addresses) == 0 || len(addresses) > maxEndpointReviewAddresses {
		return WireGuardEndpointReview{}, ErrEndpointReview
	}
	seen := map[string]bool{}
	canonical := make([]string, 0, len(addresses))
	for _, address := range addresses {
		address = address.Unmap()
		if !publicfetch.PublicAddress(address) {
			return WireGuardEndpointReview{}, ErrEndpointReview
		}
		value := address.String()
		if !seen[value] {
			seen[value] = true
			canonical = append(canonical, value)
		}
	}
	sort.Strings(canonical)
	now := time.Now().UTC()
	return WireGuardEndpointReview{
		Host: host, Port: uint16(portValue), Addresses: canonical, ExpiresAt: now.Add(endpointReviewTTL),
		profileBinding: digest(profile), original: fields["Peer.Endpoint"], resolved: append([]string(nil), canonical...),
		pinnedPort: uint16(portValue), validUntil: now.Add(endpointReviewTTL), valid: true,
	}, nil
}

// WithResolvedWireGuardCandidate validates the original profile and in-memory
// review again, replaces only Peer.Endpoint with the selected literal and then
// delegates to the strict ephemeral candidate builder.
func WithResolvedWireGuardCandidate(ctx context.Context, profile []byte, review WireGuardEndpointReview, selected string, reviewed bool, options CandidateOptions, consume func(context.Context, WireGuardCandidate) error) error {
	if ctx == nil || !reviewed || !review.valid || review.profileBinding != digest(profile) || review.validUntil.IsZero() || !time.Now().UTC().Before(review.validUntil) {
		return ErrEndpointReview
	}
	fields, err := wireGuardFields(profile)
	if err != nil || fields["Peer.Endpoint"] != review.original {
		return ErrEndpointReview
	}
	address, err := netip.ParseAddr(selected)
	if err != nil || !publicfetch.PublicAddress(address) || !containsReviewedAddress(review.resolved, address.Unmap().String()) {
		return ErrEndpointReview
	}
	pinned, err := pinWireGuardEndpoint(profile, net.JoinHostPort(address.Unmap().String(), strconv.Itoa(int(review.pinnedPort))))
	if err != nil {
		return ErrEndpointReview
	}
	defer eraseBytes(pinned)
	return WithReviewedWireGuardCandidate(ctx, pinned, true, options, consume)
}

func containsReviewedAddress(values []string, selected string) bool {
	for _, value := range values {
		if value == selected {
			return true
		}
	}
	return false
}

func pinWireGuardEndpoint(profile []byte, endpoint string) ([]byte, error) {
	var out bytes.Buffer
	section := ""
	replaced := false
	for _, raw := range strings.Split(strings.ReplaceAll(string(profile), "\r\n", "\n"), "\n") {
		line := strings.TrimSpace(raw)
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.TrimSpace(line[1 : len(line)-1])
		}
		if section == "Peer" {
			key, _, assigned := strings.Cut(line, "=")
			if assigned && strings.TrimSpace(key) == "Endpoint" {
				if replaced {
					return nil, ErrEndpointReview
				}
				raw = "Endpoint = " + endpoint
				replaced = true
			}
		}
		out.WriteString(raw)
		out.WriteByte('\n')
	}
	if !replaced {
		return nil, ErrEndpointReview
	}
	return out.Bytes(), nil
}
