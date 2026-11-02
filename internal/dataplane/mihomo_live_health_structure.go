package dataplane

import (
	"context"
	"errors"
	"net/netip"
	"slices"
)

// This fresh comparison performs no service HTTPS and creates no health
// evidence. The initial Commit may publish no ACTIVE/committed state: Manager
// must still run mandatory postpromotion HTTPS AFTER the actual config CAS.
func (r *mihomoLiveResource) currentPromotedStructure(ctx context.Context) error {
	return r.liveHealthStructure(ctx, nil, nil)
}

// A supplied policy/DNS vector compares the completed Health phase's exact
// original candidate. Nil selects only a freshly observed ACTIVE binding for
// Commit's closing structural comparison; no observation crosses config CAS.
func (r *mihomoLiveResource) liveHealthStructure(ctx context.Context, policy *nodeTransitPolicyAuthority, expectedDNS map[string][]netip.Addr) error {
	if err := r.compiledCurrent(true); err != nil {
		return err
	}
	if err := r.currentBeforeStart(ctx); err != nil {
		return err
	}
	if err := r.liveOwnersReadOnly(ctx, nil); err != nil {
		return err
	}
	a, state := r.proxy, r.definition.Policy
	if policy == nil {
		binding, exists, err := a.readPolicyBinding(state)
		if err != nil || !exists || binding.Phase != "active" {
			return errors.Join(ErrProxyPolicyUnknown, err)
		}
		policy, err = a.captureNodeTransitPolicyAuthority(ctx, r.definition.Plan.PlanID, state, "", binding.Generation)
		if err != nil || policy == nil || policy.candidate {
			return errors.Join(ErrProxyPolicyUnknown, err)
		}
	}
	if proxyPolicyDigest(state) != policy.digest {
		return ErrProxyPolicyUnknown
	}
	if err := errors.Join(policy.verify(ctx, a), a.verifyForwarding(ctx, state), verifyPolicyEvidence(ctx, a.Runner, a.ip(), state)); err != nil {
		return err
	}
	prefix, err := netip.ParsePrefix(a.TunnelCIDR)
	if err != nil || !prefix.Addr().Is4() {
		return errMihomoLiveMaterial
	}
	r.mu.Lock()
	index := r.tunIndex
	r.mu.Unlock()
	probes := mihomoRequiredProbes(r.definition.Service)
	seen := make(map[string]bool, len(probes))
	for _, probe := range probes {
		addresses, err := resolveNodeServiceIPv4(ctx, probe.URL, a.Resolver)
		if err != nil || len(addresses) == 0 || expectedDNS != nil && !mihomoHealthDNSMatches(expectedDNS, probe.URL, addresses) {
			return errors.Join(ErrNodeEndpointChanged, err)
		}
		seen[probe.URL] = true
		for _, destination := range addresses {
			if !nodeRouterPinInScope(destination, state.Prefixes) {
				return ErrNodeResourceDenied
			}
			if err := checkNodeResourceURL(ctx, probe.URL, destination); err != nil {
				return err
			}
			request := nodeRouterHTTPSRequest{Interface: a.Interface, IfIndex: index, Source: prefix.Addr(), Destination: destination}
			if err := nodeRouterAssignedSource(ctx, request, nodeRouterHTTPSOptions{}); err != nil {
				return err
			}
			if err := nodeRouterReturnPath(ctx, a.Interface); err != nil {
				return err
			}
			if err := r.backendDisjoint(ctx, request.Source, request.Destination); err != nil {
				return err
			}
		}
		closing, err := resolveNodeServiceIPv4(ctx, probe.URL, a.Resolver)
		if err != nil || !slices.Equal(addresses, closing) || expectedDNS != nil && !mihomoHealthDNSMatches(expectedDNS, probe.URL, closing) {
			return errors.Join(ErrNodeEndpointChanged, err)
		}
	}
	if expectedDNS != nil && len(seen) != len(expectedDNS) {
		return ErrNodeEndpointChanged
	}
	if err := errors.Join(policy.verify(ctx, a), a.verifyForwarding(ctx, state), verifyPolicyEvidence(ctx, a.Runner, a.ip(), state), r.liveOwnersReadOnly(ctx, nil)); err != nil {
		return err
	}
	if err := r.currentBeforeStart(ctx); err != nil {
		return err
	}
	return r.compiledCurrent(true)
}
