package dataplane

import (
	"context"
	"errors"
	"slices"
)

type usqueHealthRunner struct{ runner NFQWS2Runner }

func (r usqueHealthRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	if err := requireOwnedUSQUEReviewGuard(ctx); err != nil {
		return nil, err
	}
	data, err := r.runner.Run(ctx, name, append([]string(nil), args...)...)
	return data, errors.Join(err, requireOwnedUSQUEReviewGuard(ctx))
}

func (a *ProxyTunnelAdapter) withUSQUEHealthPolicy(ctx context.Context, state PolicyState, engine ProcessSpec) context.Context {
	frozen := *a
	state.Prefixes, state.Exclusions, state.Rules = slices.Clone(state.Prefixes), slices.Clone(state.Exclusions), slices.Clone(state.Rules)
	if state.Forwarding != nil {
		copy := *state.Forwarding
		copy.Rules = slices.Clone(copy.Rules)
		state.Forwarding = &copy
	}
	if state.WireGuardEndpoint != nil {
		copy := *state.WireGuardEndpoint
		state.WireGuardEndpoint = &copy
	}
	engine.Args = slices.Clone(engine.Args)
	return context.WithValue(ctx, usqueLiveHealthPolicyKey{}, func(c context.Context) error {
		return frozen.verifyUSQUEHealthRuntime(c, state, engine)
	})
}

func (a *ProxyTunnelAdapter) healthOwnedUSQUEWithPolicy(ctx context.Context, plan Plan, state PolicyState, engine ProcessSpec, roots ...string) error {
	return a.healthOwnedUSQUE(a.withUSQUEHealthPolicy(ctx, state, engine), plan, roots...)
}

func (a *ProxyTunnelAdapter) verifyUSQUECandidatePolicy(ctx context.Context, plan Plan, root string, state PolicyState) error {
	if err := a.checkUSQUEPlanAuthority(ctx, plan); err != nil {
		return err
	}
	selected, err := a.usqueHealthTransport(root)
	if err != nil {
		return err
	}
	return a.verifyUSQUEHealthRuntime(ctx, state, a.engineProcessWithTransport(selected))
}

func (a *ProxyTunnelAdapter) commitOwnedUSQUEHealthWithPolicy(ctx context.Context, plan Plan, root string, captured []byte, state PolicyState) error {
	if err := a.checkUSQUEPlanAuthority(ctx, plan); err != nil {
		return err
	}
	selected, err := a.usqueHealthTransport(root)
	if err != nil {
		return err
	}
	return a.commitOwnedUSQUEHealth(a.withUSQUEHealthPolicy(ctx, state, a.engineProcessWithTransport(selected)), plan, root, captured)
}

func (a *ProxyTunnelAdapter) freezeUSQUEHealthPlan(plan Plan) Plan {
	if a.ID() == "usque" {
		plan.Routes = cloneNetworkPolicyRoutes(plan.Routes)
		plan.LAN = CloneLANPolicyRuntime(plan.LAN)
	}
	return plan
}

// Active health and reconciliation bind even an ordinary catalog route to the
// reviewed WAN. Closing review checks fence matching-profile callbacks that
// revoke the operation while returning a successful observation.
func (a *ProxyTunnelAdapter) checkUSQUEPlanAuthority(ctx context.Context, plan Plan) error {
	if a.ID() != "usque" {
		return nil
	}
	if err := requireOwnedUSQUEReviewGuard(ctx); err != nil {
		return err
	}
	if err := verifyNetworkProfile(ctx, plan.NetworkProfileID, a.FreshProfile); err != nil {
		return err
	}
	return requireOwnedUSQUEReviewGuard(ctx)
}

// Only active health uses this guarded view. Receipt-owned rollback retains its
// existing independent cleanup checks and does not acquire new probe authority.
func (a *ProxyTunnelAdapter) verifyUSQUEHealthRuntime(ctx context.Context, state PolicyState, engine ProcessSpec) error {
	if err := requireOwnedUSQUEReviewGuard(ctx); err != nil {
		return err
	}
	view := *a
	view.Runner = usqueHealthRunner{runner: a.Runner}
	if a.LANBridgeMembers != nil {
		members := a.LANBridgeMembers
		view.LANBridgeMembers = func(c context.Context, bridge string) ([]string, error) {
			if err := requireOwnedUSQUEReviewGuard(c); err != nil {
				return nil, err
			}
			values, err := members(c, bridge)
			return values, errors.Join(err, requireOwnedUSQUEReviewGuard(c))
		}
	}
	processes := &usqueHealthProcesses{ProcessController: a.Processes, ctx: ctx}
	view.Processes = processes
	probe := a.SOCKSProbe
	if probe == nil {
		probe = probeSOCKS5
	}
	view.SOCKSProbe = func(c context.Context, address string) error {
		if err := requireOwnedUSQUEReviewGuard(c); err != nil {
			return err
		}
		return errors.Join(probe(c, address), requireOwnedUSQUEReviewGuard(c))
	}
	return errors.Join(view.verifyHealthRuntimeProcess(ctx, state, engine), processes.failure(), requireOwnedUSQUEReviewGuard(ctx))
}
