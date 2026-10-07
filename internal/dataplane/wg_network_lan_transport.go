package dataplane

import (
	"context"
	"errors"
	"reflect"
	"strings"
)

// VerifyLANPolicyTransport is a read-only proof for a single observed outer
// WG/AWG RPDB selector. It grants neither service-consumer admission nor LAN
// namespace completeness. The LAN owner supplies its separate TransportCheck
// and retains its full namespace and physical-scope checks.
func (a *WARPWireGuardAdapter) VerifyLANPolicyTransport(ctx context.Context, plan *LANPolicyRuntimePlan, family int, ruleLine string) error {
	if a == nil || a.Runner == nil || a.ID() != "wireguard" && a.ID() != "amneziawg" || family != 4 && family != 6 || len(ruleLine) == 0 || len(ruleLine) > 2048 || strings.ContainsAny(ruleLine, "\r\n\x00") {
		return ErrWGNetworkPolicy
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	runner := reflect.ValueOf(a.Runner)
	switch runner.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		if runner.IsNil() {
			return ErrWGNetworkPolicy
		}
	}
	lan := CloneLANPolicyRuntime(plan)
	if err := ValidateLANPolicyRuntime(lan); err != nil {
		return err
	}
	if err := a.checkWGPolicyOperation(); err != nil {
		return err
	}
	state, owned, err := a.deactivationOwnership(ctx)
	if err != nil || !owned || state.NetworkPolicyGeneration == "" || state.WireGuardEndpoint == nil {
		return errors.Join(err, ErrWGNetworkPolicy)
	}
	ref, err := a.committedWGPolicyReference(state)
	if err != nil {
		return err
	}
	// samePolicy intentionally ignores endpoint/runtime metadata. Bind the
	// endpoint explicitly. A pre-Commit reference can have no runtime digest;
	// deactivationOwnership still requires the committed digest to match bytes.
	if !reflect.DeepEqual(lan, ref.FrozenLAN) || lan.Generation != state.NetworkPolicyGeneration || !reflect.DeepEqual(state.WireGuardEndpoint, ref.Policy.WireGuardEndpoint) || ref.Policy.RuntimeConfigSHA256 != "" && state.RuntimeConfigSHA256 != ref.Policy.RuntimeConfigSHA256 {
		return ErrWGNetworkPolicy
	}
	e := state.WireGuardEndpoint
	spec, err := a.endpointSpec()
	if err != nil || e.Table != spec.EndpointTable || !e.matchesRule(family, ruleLine) {
		return errors.Join(err, ErrWGNetworkPolicy)
	}
	boot, err := a.wgPolicyBoot()
	if err != nil || boot != ref.Boot {
		return errors.Join(err, ErrPolicyAdditionUnknown)
	}
	status, err := a.inspectWGPolicyReference(ctx, ref, "")
	if err != nil || !status.Complete || status.Unknown || status.Removed || status.Promoted || status.Pending != 0 {
		return errors.Join(err, ErrPolicyAdditionUnknown)
	}
	active, err := a.deactivationInterfaceActive(ctx)
	if err != nil || !active {
		return errors.Join(err, ErrWGNetworkPolicy)
	}
	// The observation alone is insufficient: reread both complete numeric
	// RPDBs and reject duplicates or any other occupant of this reserved slot.
	count := 0
	for _, observedFamily := range []int{4, 6} {
		lines, err := readPolicyRules(ctx, numericPolicyReadRunner{base: a.Runner}, a.ip(), observedFamily)
		if err != nil {
			return err
		}
		for _, line := range lines {
			if strings.TrimSpace(line) == "" {
				continue
			}
			priority, ok := policyLinePriority(line)
			if !ok {
				return ErrWGNetworkPolicy
			}
			if priority != e.Priority {
				continue
			}
			if !e.matchesRule(observedFamily, line) {
				return ErrWGNetworkPolicy
			}
			count++
		}
	}
	if count != 1 {
		return ErrWGNetworkPolicy
	}
	if err := a.verifyWGNetworkForwarding(ctx, state); err != nil {
		return err
	}
	// This also checks the complete transport table and selector dependencies
	// in both families, exact host route, live fwmark and public-key identity.
	return errors.Join(a.verifyWGEndpoint(ctx, e, ref.FrozenLAN), ctx.Err())
}
