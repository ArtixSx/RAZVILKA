package cloudflareprovider

import (
	"context"
	"errors"
	"net"
	"net/netip"
)

var ErrReviewedCandidate = errors.New("reviewed WireGuard candidate is unavailable or unsafe")

// WithReviewedWireGuardCandidate builds an ephemeral scanner candidate from
// bytes explicitly supplied for this operation. A passive Store import never
// gains runtime capability. The reviewed flag must come from a separate,
// conscious confirmation by the caller; no state is persisted here.
func WithReviewedWireGuardCandidate(ctx context.Context, profile []byte, reviewed bool, options CandidateOptions, consume func(context.Context, WireGuardCandidate) error) error {
	if !reviewed || consume == nil || ctx == nil {
		return ErrReviewedCandidate
	}
	parsed, err := ParseImport(SourceWireGuard, profile)
	if err != nil {
		return ErrReviewedCandidate
	}
	defer eraseBytes(parsed.raw)
	view := parsed.Preview()
	fields, err := wireGuardFields(profile)
	if err != nil || fields["Peer.PresharedKey"] != "" {
		return ErrReviewedCandidate
	}
	privateKey, err := wireGuardKey(fields["Interface.PrivateKey"])
	if err != nil {
		return ErrReviewedCandidate
	}
	defer eraseBytes(privateKey)
	peerPublicKey, err := wireGuardKey(fields["Peer.PublicKey"])
	if err != nil {
		return ErrReviewedCandidate
	}
	defer eraseBytes(peerPublicKey)
	addressText, err := prefixes(fields["Interface.Address"])
	if err != nil {
		return ErrReviewedCandidate
	}
	allowed, err := prefixes(fields["Peer.AllowedIPs"])
	if err != nil || !reviewedFullTunnel(allowed) {
		return ErrReviewedCandidate
	}
	host, port, err := net.SplitHostPort(fields["Peer.Endpoint"])
	endpointAddress, addressErr := netip.ParseAddr(host)
	endpoint, endpointErr := netip.ParseAddrPort(net.JoinHostPort(endpointAddress.String(), port))
	if err != nil || addressErr != nil || endpointErr != nil || !safeReviewedEndpoint(endpointAddress) {
		return ErrReviewedCandidate
	}
	material := TunnelMaterial{
		privateKey: privateKey, peerPublicKey: peerPublicKey,
		endpoints: []netip.AddrPort{endpoint}, binding: "reviewed-wireguard:" + digest(profile),
	}
	for _, raw := range addressText {
		prefix, parseErr := netip.ParsePrefix(raw)
		if parseErr != nil || !safeReviewedTunnelAddress(prefix) {
			return ErrReviewedCandidate
		}
		material.addresses = append(material.addresses, prefix)
	}
	if _, err := firstReviewedIPv4(material.addresses); err != nil {
		return err
	}
	accountID := "cf-" + digest([]byte(material.binding + "\x00" + view.PublicKeyFingerprint))[:32]
	candidate, err := wireGuardCandidateFromMaterial(accountID, material, options)
	if err != nil {
		return ErrReviewedCandidate
	}
	defer candidate.erase()
	if err := ctx.Err(); err != nil {
		return err
	}
	return consume(ctx, candidate)
}

func reviewedFullTunnel(values []string) bool {
	if len(values) < 1 || len(values) > 2 {
		return false
	}
	seen4, seen6 := false, false
	for _, value := range values {
		switch value {
		case "0.0.0.0/0":
			seen4 = true
		case "::/0":
			seen6 = true
		default:
			return false
		}
	}
	return seen4 && (len(values) == 1 || seen6)
}

func safeReviewedEndpoint(address netip.Addr) bool {
	return address.IsValid() && address.Zone() == "" && address.IsGlobalUnicast() && !address.IsPrivate() && !address.IsLoopback() && !address.IsLinkLocalUnicast() && !address.Is4In6()
}

func safeReviewedTunnelAddress(prefix netip.Prefix) bool {
	address := prefix.Addr()
	return address.IsValid() && address.Zone() == "" && address.IsGlobalUnicast() && !address.IsLoopback() && !address.IsLinkLocalUnicast() && !address.Is4In6()
}

func firstReviewedIPv4(values []netip.Prefix) (netip.Prefix, error) {
	for _, value := range values {
		if value.Addr().Is4() {
			return value, nil
		}
	}
	return netip.Prefix{}, ErrReviewedCandidate
}
