package dataplane

import (
	"context"
	"sync/atomic"
)

// Private operation-local documentary writer association. The public entry
// mints this only AFTER real reader8 fleet admission and original guard,
// outside every leaf lock. It expires before that Manager operation returns;
// it is not put in a context or accepted by any native/effect/flow API.
type domainTCPContinuationAdmission struct {
	self    *domainTCPContinuationAdmission
	manager *Manager
	request context.Context
	prior   *DomainTCPDetachedStandby
	digest  string
	cursor  *domainTCPGlobalSuccessor
	active  atomic.Bool
}

// Caller already holds Manager.operation and has completed fleet/guard reads.
// Initial/retry publication is synchronous before issuing the action. Later
// resource publications hold scope.mu; scope.close takes that barrier and
// joins its original participants before this operation-local carrier ends.
// Atomic revocation alone would not join an already-entered publisher.
func withDomainContinuationAdmission(ctx context.Context, m *Manager, p Plan, prior *DomainTCPDetachedStandby, use func(*domainTCPContinuationAdmission) error) error {
	if ctx == nil || m == nil || prior == nil || prior.self != prior || use == nil || xraySelectedTCPFinite(ctx) != nil {
		return ErrPolicyAdditionUnknown
	}
	a := &domainTCPContinuationAdmission{manager: m, request: ctx, prior: prior, digest: p.Digest}
	a.self = a
	a.active.Store(true)
	defer a.active.Store(false)
	return use(a)
}

func (a *domainTCPContinuationAdmission) initial(ctx context.Context, m *Manager, p Plan, prior *DomainTCPDetachedStandby) error {
	if a == nil || a.self != a || !a.active.Load() || a.manager != m || !sameNetworkPolicyDependency(a.request, ctx) || a.prior != prior || a.digest != p.Digest || ctx == nil || ctx.Err() != nil {
		return ErrPolicyAdditionUnknown
	}
	return nil
}

func (a *domainTCPContinuationAdmission) current(c *domainTCPGlobalSuccessor, ctx context.Context) error {
	if a == nil || a.self != a || !a.active.Load() || a.request == nil || ctx == nil || a.cursor != c || c == nil || c.scope == nil || c.scope.ctx == nil || a.manager != c.scope.manager || a.digest != c.scope.plan.Digest || !sameNetworkPolicyDependency(a.request, c.request) || !sameNetworkPolicyDependency(ctx, c.scope.ctx) || a.request.Err() != nil || ctx.Err() != nil {
		return ErrPolicyAdditionUnknown
	}
	return nil
}
