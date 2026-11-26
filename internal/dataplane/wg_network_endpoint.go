package dataplane

import (
	"context"
	"errors"
	"strconv"
)

// Static table coordinates are never evidence of an empty or owned table.
// Both families and every remaining numeric selector are inspected afresh.
func (a *WARPWireGuardAdapter) inspectWGNetworkTransportTable(ctx context.Context, table int, owned *WGEndpointState, frozen ...*LANPolicyRuntimePlan) error {
	if len(frozen) > 1 {
		return ErrWGNetworkPolicy
	}
	var lan *LANPolicyRuntimePlan
	if len(frozen) == 1 && frozen[0] != nil {
		lan = CloneLANPolicyRuntime(frozen[0])
		if err := ValidateLANPolicyRuntime(lan); err != nil {
			return err
		}
	}
	for _, family := range []int{4, 6} {
		proof := PolicyState{Table: table, WireGuardEndpoint: owned}
		var proofErr error
		if lan != nil {
			proof.NetworkPolicyGeneration = lan.Generation
			proofErr = AssertPolicyDefaultUnreferencedWithLAN(ctx, a.Runner, a.ip(), proof, family, lan)
		} else {
			proofErr = AssertPolicyDefaultUnreferenced(ctx, a.Runner, a.ip(), proof, family)
		}
		if proofErr != nil {
			return proofErr
		}
		args := []string{"-N"}
		if family == 6 {
			args = append(args, "-6")
		}
		args = append(args, "-j", "route", "show", "table", strconv.Itoa(table))
		routes, err := a.readWGEndpointRoutes(ctx, args...)
		if err != nil {
			return err
		}
		if len(routes) == 0 {
			continue
		}
		if owned == nil || owned.Table != table || owned.address().Is4() != (family == 4) {
			return ErrWGNetworkPolicy
		}
		observer := *a
		observer.Runner = numericPolicyReadRunner{base: a.Runner}
		route, rule, err := observer.inspectWGEndpoint(ctx, owned)
		if err != nil || !route || !rule {
			return errors.Join(err, ErrWGNetworkPolicy)
		}
		// The full table response must be the same route as exact-host readback.
		if !wgEndpointRouteMatches(*owned, routes[0]) {
			return ErrWGNetworkPolicy
		}
	}
	return ctx.Err()
}

func (a *WARPWireGuardAdapter) preflightWGNetworkTransport(ctx context.Context, endpoint *WGEndpointState, plan Plan) error {
	if endpoint == nil {
		return ErrWGNetworkPolicy
	}
	if err := checkWGNetworkReview(ctx); err != nil {
		return err
	}
	lan, err := plan.FrozenLAN()
	if err != nil {
		return err
	}
	if err := a.checkWGPolicyOperation(); err != nil {
		return err
	}
	var ownedEndpoint *WGEndpointState
	serviceState := PolicyState{Interface: a.interfaceName(), Table: a.table(), NetworkPolicyGeneration: lan.Generation}
	wanted := 0
	_, exists, err := a.loadPolicyState()
	if err != nil {
		return err
	}
	if exists {
		state, owned, err := a.deactivationOwnership(ctx)
		if err != nil || !owned {
			return errors.Join(err, ErrWGNetworkPolicy)
		}
		ref, err := a.committedWGPolicyReference(state)
		if err != nil {
			return err
		}
		boot, err := a.wgPolicyBoot()
		if err != nil || boot != ref.Boot {
			return errors.Join(err, ErrPolicyAdditionUnknown)
		}
		status, err := a.inspectWGPolicyReference(ctx, ref, "")
		if err != nil || !status.Complete || status.Unknown || status.Promoted || status.Removed {
			return errors.Join(err, ErrPolicyAdditionUnknown)
		}
		ownedEndpoint = state.WireGuardEndpoint
		serviceState, wanted = state, 1
		if ownedEndpoint == nil {
			return ErrWGNetworkPolicy
		}
		active, err := a.deactivationInterfaceActive(ctx)
		if err != nil || !active {
			return errors.Join(err, ErrWGNetworkPolicy)
		}
		if err := a.verifyWGEndpoint(ctx, ownedEndpoint, ref.FrozenLAN); err != nil {
			return err
		}
	}
	if err := a.verifyWGNetworkServiceTables(ctx, serviceState, wanted); err != nil {
		return err
	}
	return a.inspectWGNetworkTransportTable(ctx, endpoint.Table, ownedEndpoint, lan)
}
