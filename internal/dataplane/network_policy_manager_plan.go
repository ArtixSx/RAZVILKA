package dataplane

import (
	"net/netip"
	"slices"
)

// ValidateNetworkPolicyLAN checks frozen intent only. It does not grant kernel
// effects or prove that a physical gate is installed. A network-policy adapter
// must require this payload and independently inspect its actual runtime.
func ValidateNetworkPolicyLAN(lan *LANPolicyRuntimePlan, routes []Route) error {
	if err := ValidateLANPolicyRuntime(lan); err != nil {
		return err
	}
	for _, route := range routes {
		if route.NetworkPolicyGeneration != lan.Generation {
			return ErrNetworkPolicyAuthority
		}
		if _, _, err := NetworkPolicyRouteAuthority(Plan{Routes: []Route{route}}, adapterID(route.Resolved)); err != nil {
			return err
		}
		for _, iface := range route.Ingress {
			var gate *LANPolicyIngress
			for i := range lan.Ingress {
				if lan.Ingress[i].Interface == iface {
					gate = &lan.Ingress[i]
					break
				}
			}
			if gate == nil {
				return ErrNetworkPolicyAuthority
			}
			for _, source := range route.Sources {
				prefix, err := netip.ParsePrefix(source)
				if err != nil {
					return ErrNetworkPolicyAuthority
				}
				covered := false
				for _, value := range gate.Sources {
					parent, _ := netip.ParsePrefix(value) // shared plan was validated
					covered = covered || parent.Addr().BitLen() == prefix.Addr().BitLen() && parent.Bits() <= prefix.Bits() && parent.Contains(prefix.Addr())
				}
				if !covered {
					return ErrNetworkPolicyAuthority
				}
			}
		}
	}
	return nil
}

// FrozenLAN returns a defensive, shape-checked shared payload. Missing payload
// is always an error; scalar generation and review callbacks cannot replace it.
func (p Plan) FrozenLAN() (*LANPolicyRuntimePlan, error) {
	if err := ValidateNetworkPolicyLAN(p.LAN, p.Routes); err != nil {
		return nil, err
	}
	return CloneLANPolicyRuntime(p.LAN), nil
}

func (p RoutePlan) FrozenLAN() (*LANPolicyRuntimePlan, error) {
	if err := ValidateNetworkPolicyLAN(p.LAN, p.Routes); err != nil {
		return nil, err
	}
	return CloneLANPolicyRuntime(p.LAN), nil
}

func cloneNetworkPolicyRoutes(routes []Route) []Route {
	result := slices.Clone(routes)
	for i := range result {
		r := &result[i]
		if r.ProbeService != nil {
			service := copyProxyPredicateService(*r.ProbeService)
			r.ProbeService = &service
		}
		r.Domains = slices.Clone(r.Domains)
		r.CIDRs = slices.Clone(r.CIDRs)
		r.SourceRefs = slices.Clone(r.SourceRefs)
		r.Sources = slices.Clone(r.Sources)
		r.Ingress = slices.Clone(r.Ingress)
	}
	return result
}
