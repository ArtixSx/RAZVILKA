package dataplane

import (
	"context"
	"errors"
	"net/netip"
	"strings"
)

// A reviewed network program must not install selectors for destinations that
// the one peer cannot carry. Local tunnel addresses are also required for an
// independent, device-bound health probe in every selected address family.
func wgNetworkProfileSources(ctx context.Context, profile string, destinations []string) ([]netip.Addr, error) {
	_, addresses, _, err := nativeWGConfig(profile)
	if err != nil {
		return nil, err
	}
	section, allowedText := "", ""
	peers := 0
	for _, line := range strings.Split(profile, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.TrimSpace(line[1 : len(line)-1])
			if section == "Peer" {
				peers++
			}
			continue
		}
		key, value, found := strings.Cut(line, "=")
		if found && section == "Peer" && strings.EqualFold(strings.TrimSpace(key), "AllowedIPs") {
			if allowedText != "" {
				return nil, errors.New("network policy requires one unambiguous WireGuard peer AllowedIPs")
			}
			allowedText = strings.TrimSpace(value)
		}
	}
	if peers != 1 || allowedText == "" || len(destinations) == 0 || len(destinations) > maxPolicyPrefixes {
		return nil, errors.New("network policy requires one WireGuard peer and bounded destinations")
	}
	var allowed []netip.Prefix
	for _, value := range strings.Split(allowedText, ",") {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(value))
		if err != nil || prefix.Addr().Is4In6() || prefix.Addr().Zone() != "" {
			return nil, errors.New("invalid WireGuard network AllowedIPs")
		}
		allowed = append(allowed, prefix.Masked())
		if len(allowed) > maxPolicyPrefixes {
			return nil, errors.New("WireGuard network AllowedIPs bound exceeded")
		}
	}
	families := map[bool]bool{}
	memo := map[netip.Prefix]bool{}
	for _, value := range destinations {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		prefix, err := netip.ParsePrefix(value)
		if err != nil || prefix.Addr().Is4In6() || prefix != prefix.Masked() {
			return nil, errors.New("invalid WireGuard network destination")
		}
		if !wgAllowedIPsCover(ctx, prefix, allowed, memo) {
			return nil, errors.Join(ctx.Err(), errors.New("WireGuard peer AllowedIPs do not cover the reviewed network policy"))
		}
		families[prefix.Addr().Is4()] = true
	}
	sources := map[bool]netip.Addr{}
	for _, value := range addresses {
		prefix, err := netip.ParsePrefix(value)
		if err != nil || prefix.Addr().Is4In6() || !prefix.Addr().IsGlobalUnicast() || prefix.Addr().IsUnspecified() {
			return nil, errors.New("invalid WireGuard network health source")
		}
		family := prefix.Addr().Is4()
		if !sources[family].IsValid() {
			sources[family] = prefix.Addr()
		}
	}
	var out []netip.Addr
	for _, family := range []bool{true, false} {
		if families[family] {
			if !sources[family].IsValid() {
				return nil, errors.New("WireGuard network policy lacks a tunnel health address for a selected family")
			}
			control := wgNetworkUDPTarget(sources[family]).Addr()
			if !wgAllowedIPsCover(ctx, netip.PrefixFrom(control, control.BitLen()), allowed, memo) {
				return nil, errors.Join(ctx.Err(), errors.New("WireGuard peer AllowedIPs lack independent network UDP health coverage"))
			}
			out = append(out, sources[family])
		}
	}
	return out, ctx.Err()
}

func wgAllowedIPsCover(ctx context.Context, destination netip.Prefix, allowed []netip.Prefix, memo map[netip.Prefix]bool) bool {
	if ctx.Err() != nil {
		return false
	}
	if covered, exists := memo[destination]; exists {
		return covered
	}
	var overlap []netip.Prefix
	for _, prefix := range allowed {
		if prefix.Addr().Is4() != destination.Addr().Is4() || !prefix.Overlaps(destination) {
			continue
		}
		if prefix.Bits() <= destination.Bits() {
			memo[destination] = true
			return true
		}
		overlap = append(overlap, prefix)
	}
	if len(overlap) == 0 || destination.IsSingleIP() {
		memo[destination] = false
		return false
	}
	bits := destination.Bits()
	left := netip.PrefixFrom(destination.Addr(), bits+1)
	var right netip.Addr
	if destination.Addr().Is4() {
		bytes := destination.Addr().As4()
		bytes[bits/8] |= 1 << (7 - bits%8)
		right = netip.AddrFrom4(bytes)
	} else {
		bytes := destination.Addr().As16()
		bytes[bits/8] |= 1 << (7 - bits%8)
		right = netip.AddrFrom16(bytes)
	}
	covered := wgAllowedIPsCover(ctx, left, overlap, memo) && wgAllowedIPsCover(ctx, netip.PrefixFrom(right, bits+1), overlap, memo)
	memo[destination] = covered
	return covered
}
