package dataplane

import (
	"context"
	"errors"
)

func (a *ProxyTunnelAdapter) endpointExclusionsOnly(old, next PolicyState) bool {
	if a.ID() != "sing-box" {
		return false
	}
	// Compare the entire frozen state, including interface, source/destination
	// grants, network generation/role and recorded RPDB coordinates. Only DNS
	// endpoint exclusions may differ; no broader refresh can retain this lease.
	next.Exclusions = old.Exclusions
	return proxyPolicyDigest(old) == proxyPolicyDigest(next)
}

func (a *ProxyTunnelAdapter) refreshEndpointExclusions(ctx context.Context, plan Plan, old, next PolicyState) (bool, error) {
	// This branch has no legacy intent-based cleanup. Both the complete current
	// addition receipt and the exact original firewall lease must still exist.
	binding, exists, err := a.readPolicyBinding(old)
	if err != nil || !exists || binding.Phase != "active" {
		return false, errors.Join(ErrProxyPolicyUnknown, err)
	}
	if err := a.verifyCommittedReceipt(ctx, old); err != nil {
		return false, err
	}
	if err := a.verifyForwarding(ctx, old); err != nil {
		return false, err
	}
	if err := a.checkPlanNetwork(ctx, plan); err != nil {
		return false, err
	}
	if err := a.removeCommittedPolicyAddition(ctx, old); err != nil {
		return false, err
	}
	// Unknown/partial additions keep their pending reference and fence. Never
	// infer a restoration grant from an absent ledger after an error or crash.
	if err := a.applyRetainedPolicyGeneration(ctx, next, nil, true); err != nil {
		return false, err
	}
	rollback := func(cause error) error {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), a.timeout())
		defer cancel()
		if err := a.removeCommittedPolicyAddition(cleanup, next); err != nil {
			return errors.Join(cause, err)
		}
		return errors.Join(cause, a.applyRetainedPolicyGeneration(cleanup, old, nil, true))
	}
	if err := a.healthState(ctx, plan, next); err != nil {
		return false, rollback(err)
	}
	if err := errors.Join(a.checkPlanNetwork(ctx, plan), a.verifyCommittedReceipt(ctx, next), a.verifyForwarding(ctx, next)); err != nil {
		return false, rollback(err)
	}
	return true, nil
}
