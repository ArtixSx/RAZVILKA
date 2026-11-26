package dataplane

import (
	"context"
	"errors"
	"net/netip"
)

var ErrWGNetworkPolicy = errors.New("WireGuard network policy requires reviewed scope, isolated transport pin and complete family health")

func checkWGNetworkReview(ctx context.Context) error {
	guard, ok := ctx.Value(reviewGuardKey{}).(func(context.Context) error)
	if !ok || guard == nil {
		return ErrWGNetworkPolicy
	}
	return errors.Join(ctx.Err(), checkWGNamedReviewContext(ctx), guard(ctx))
}

// Background recovery/address refresh cannot acquire a different LAN scope.
// Changing classifier intent requires the complete Apply transaction.
func (a *WARPWireGuardAdapter) verifyWGNetworkReferenceScope(plan Plan, ref warpWGPolicyReference) error {
	generation, networkDefault, err := NetworkPolicyRouteAuthority(plan, a.ID())
	if err != nil || generation != ref.Policy.NetworkPolicyGeneration || networkDefault != ref.Policy.NetworkDefault {
		return errors.Join(err, ErrWGNetworkPolicy)
	}
	if generation == "" {
		return nil
	}
	lan, err := plan.FrozenLAN()
	if err != nil || ref.FrozenLAN == nil || lan.Digest != ref.FrozenLAN.Digest || lan.Generation != ref.FrozenLAN.Generation {
		return errors.Join(err, ErrWGNetworkPolicy)
	}
	return nil
}

func (a *WARPWireGuardAdapter) wgNetworkPolicySources(ctx context.Context, plan Plan, profile string, state PolicyState) ([]netip.Addr, error) {
	generation, networkDefault, err := NetworkPolicyRouteAuthority(plan, a.ID())
	if err != nil {
		return nil, err
	}
	if generation != state.NetworkPolicyGeneration || networkDefault != state.NetworkDefault {
		return nil, ErrWGNetworkPolicy
	}
	if generation == "" {
		return nil, nil
	}
	if _, err := plan.FrozenLAN(); err != nil {
		return nil, err
	}
	if err := checkWGNetworkReview(ctx); err != nil {
		return nil, err
	}
	if a.ID() != "wireguard" && a.ID() != "amneziawg" || state.WireGuardEndpoint == nil || state.WireGuardEndpoint.Table == state.Table || len(state.Exclusions) != 0 {
		return nil, ErrWGNetworkPolicy
	}
	if err := a.validWGEndpoint(state.WireGuardEndpoint, []byte(profile)); err != nil {
		return nil, err
	}
	sources, err := wgNetworkProfileSources(ctx, profile, state.Prefixes)
	if err != nil {
		return nil, err
	}
	for _, source := range sources {
		if wgNetworkUDPTarget(source).Addr() == state.WireGuardEndpoint.address() {
			return nil, ErrWGNetworkPolicy
		}
	}
	return sources, nil
}

// The immutable reference binds the complete LAN intent. Scalar generation or
// a callback is never enough to explain negative rules at an endpoint table.
func (a *WARPWireGuardAdapter) wgFrozenLANForState(state PolicyState, frozen ...*LANPolicyRuntimePlan) (*LANPolicyRuntimePlan, error) {
	if len(frozen) > 1 {
		return nil, ErrWGNetworkPolicy
	}
	var lan *LANPolicyRuntimePlan
	if len(frozen) == 1 {
		lan = CloneLANPolicyRuntime(frozen[0])
	}
	if state.NetworkPolicyGeneration == "" {
		if lan != nil {
			return nil, ErrWGNetworkPolicy
		}
		return nil, nil
	}
	role := "override"
	if state.NetworkDefault {
		role = "default"
	}
	var routes []Route
	for _, rule := range effectivePolicyRules(state) {
		routes = append(routes, Route{Resolved: a.ID(), CIDRs: []string{rule.Destination}, Sources: []string{rule.Source}, Ingress: []string{rule.Ingress}, NetworkPolicyGeneration: state.NetworkPolicyGeneration, NetworkPolicyRole: role})
	}
	if len(routes) == 0 {
		return nil, ErrWGNetworkPolicy
	}
	if err := ValidateNetworkPolicyLAN(lan, routes); err != nil {
		return nil, err
	}
	return lan, nil
}
