package dataplane

import (
	"context"
	"errors"
)

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
