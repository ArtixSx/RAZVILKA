package dataplane

import (
	"encoding/hex"
	"errors"
	"net/netip"
	"slices"
	"strings"
)

var ErrNetworkPolicyAuthority = errors.New("compiled network policy scope requires reviewed physical LAN authority")

// These coordinates describe the LAN owner's proposed gate. Their presence
// does not prove that firmware leaves the bits free or that a gate is installed.
// The gate participant must inspect collisions and acknowledge its exact effects.
const (
	networkPolicyManagedMark uint32 = 0x20000000
	networkPolicyGateMask    uint32 = 0x28000000
	LANPolicyGateMatch              = "0x20000000/0x28000000"
)

func validNetworkPolicyGeneration(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == 32 && strings.ToLower(value) == value
}

func validPolicyIngress(value string) bool {
	return proxyFirewallInterface.MatchString(value) && value != "lo"
}

func routeIngresses(route Route) ([]string, error) {
	if len(route.Ingress) > 16 {
		return nil, ErrNetworkPolicyAuthority
	}
	seen := map[string]bool{}
	for _, value := range route.Ingress {
		if !validPolicyIngress(value) || seen[value] {
			return nil, ErrNetworkPolicyAuthority
		}
		seen[value] = true
	}
	if len(route.Ingress) == 0 {
		return []string{""}, nil // Legacy service semantics are preserved.
	}
	return slices.Clone(route.Ingress), nil
}

// Shape validation alone grants no effect authority. The caller binds these
// fields to its immutable review, fresh connected LAN and actual negative
// classifier receipt before passing the plan to an adapter.
func NetworkPolicyRouteAuthority(plan Plan, adapter string) (string, bool, error) {
	generation, unbound, defaultScope := "", false, false
	for _, route := range plan.Routes {
		if adapterID(route.Resolved) != adapter {
			continue
		}
		if _, err := routeIngresses(route); err != nil {
			return "", false, err
		}
		if route.NetworkPolicyGeneration == "" && route.NetworkPolicyRole == "" {
			unbound = true
			continue
		}
		if !validNetworkPolicyGeneration(route.NetworkPolicyGeneration) || route.NetworkPolicyRole != "default" && route.NetworkPolicyRole != "override" || len(route.Ingress) == 0 || len(route.Sources) == 0 || len(route.CIDRs) == 0 || len(route.Domains) != 0 {
			return "", false, ErrNetworkPolicyAuthority
		}
		if generation != "" && generation != route.NetworkPolicyGeneration {
			return "", false, ErrNetworkPolicyAuthority
		}
		for _, value := range route.Sources {
			prefix, err := netip.ParsePrefix(value)
			if err != nil || prefix != prefix.Masked() || prefix.Bits() == 0 || prefix.Addr().Is4In6() || !prefix.Addr().IsGlobalUnicast() {
				return "", false, ErrNetworkPolicyAuthority
			}
		}
		generation = route.NetworkPolicyGeneration
		defaultScope = defaultScope || route.NetworkPolicyRole == "default"
	}
	if generation != "" && unbound {
		return "", false, ErrNetworkPolicyAuthority
	}
	return generation, defaultScope, nil
}

func validNetworkPolicyState(state PolicyState) error {
	if state.NetworkPolicyGeneration == "" && !state.NetworkDefault {
		for _, rule := range state.Rules {
			if rule.Managed {
				return ErrNetworkPolicyAuthority
			}
		}
		return nil
	}
	if !validNetworkPolicyGeneration(state.NetworkPolicyGeneration) || state.RuleLayout != 2 || len(state.Rules) == 0 {
		return ErrNetworkPolicyAuthority
	}
	for _, rule := range state.Rules {
		source, err := netip.ParsePrefix(rule.Source)
		if err != nil || source.String() != rule.Source || source != source.Masked() || source.Bits() == 0 || source.Addr().Is4In6() || !source.Addr().IsGlobalUnicast() || !rule.Managed || !validPolicyIngress(rule.Ingress) || rule.Ingress == state.Interface {
			return ErrNetworkPolicyAuthority
		}
	}
	return nil
}
