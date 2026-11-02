package dataplane

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"time"

	"github.com/ArtixSx/razvilka/internal/updatecheck"
)

// Closed intent classification only. It cannot turn Ready on, grant a flow,
// create a DNS answer or replace the original native/source predicates.
func restrictedDomainTCPIntent(domain *DomainPolicyRuntimePlan, transport *SyntheticDNSTransportPlan, routes []Route) bool {
	if ValidateSyntheticDNSTransportPlan(transport, domain) != nil || len(transport.Definition.ExactNames) != 1 || len(routes) != 1 {
		return false
	}
	r := routes[0]
	if adapterID(r.Resolved) != "xray" || len(r.Domains) != 1 || r.Domains[0] != transport.Definition.ExactNames[0] || len(r.CIDRs) != 0 || r.LogicalServiceID == "" || len(r.Sources) != 1 || r.Sources[0] != netip.PrefixFrom(transport.Definition.Client, 32).String() {
		return false
	}
	matched := 0
	for _, service := range domain.Services {
		if !service.Selected {
			continue
		}
		if service.ID != r.LogicalServiceID || service.Route != r.Resolved || len(service.Domains) != 1 || service.Domains[0] != r.Domains[0] || len(service.DomainSuffixes) != 0 || len(service.CIDRs) != 0 || len(service.Sources) > 1 || len(service.Sources) == 1 && service.Sources[0] != r.Sources[0] {
			return false
		}
		matched++
	}
	return matched == 1
}

func validateDomainTCPProofPlan(p Plan) error {
	if p.Ready || p.State != "blocked" || p.Noop || p.SafeMode || p.Revision == 0 || p.LAN != nil || p.DNS != nil || p.SuspendDNS || p.DiscardDNS || len(p.RetiringAdapters) != 0 || len(p.ResourceConflicts) != 0 || !slices.Equal(p.Adapters, []string{"xray"}) || !restrictedDomainTCPIntent(p.DomainPolicy, p.SyntheticDNS, p.Routes) || len(p.Blockers) != 2 {
		return ErrDomainTransportRuntime
	}
	seen := map[string]bool{}
	for _, b := range p.Blockers {
		if seen[b.Code] {
			return ErrDomainTransportRuntime
		}
		seen[b.Code] = true
		switch b.Code {
		case "DOMAIN_POLICY_RUNTIME_UNAVAILABLE":
			if b.Adapter != scopedDNSAdapterID {
				return ErrDomainTransportRuntime
			}
		case "DOMAIN_FLOW_AUTHORITY_REQUIRED":
			if b.Adapter != "xray" {
				return ErrDomainTransportRuntime
			}
		default:
			return ErrDomainTransportRuntime
		}
	}
	return nil
}

// WithDomainTCPProofResources is a finite original Manager check, not Apply.
// It retains the genuine blocked plan/digest and exact two domain blockers;
// only the registered original source/process/capture can produce a proof.
// The trusted startup history owner must admit reader3 BEFORE a new journal.
func (m *Manager) WithDomainTCPProofResources(ctx context.Context, p Plan, history *updatecheck.ExecutionHistoryAdmission, action func(context.Context) error) error {
	if m == nil || ctx == nil || history == nil || action == nil || validateDomainTCPProofPlan(p) != nil {
		return ErrDomainTransportRuntime
	}
	deadline, bounded := ctx.Deadline()
	if !bounded || time.Until(deadline) <= 0 || time.Until(deadline) > 2*time.Minute {
		return ErrDomainTransportRuntime
	}
	// The existing retained slot bounds the restorative pool to ONE owner.
	// Unrelated checks may observe a known footprint; another domain execution
	// must not acquire native/effect resources and fail only at final handoff.
	if m.retainedXrayOwner() != nil {
		return ErrDomainPolicyTCPCaptureRetirementPending
	}
	if err := history.CheckWrite(ctx, 3); err != nil {
		return err
	}
	if err := m.beginOperation(ctx); err != nil {
		return err
	}
	defer m.endOperation()
	if m.retainedXrayOwner() != nil {
		return ErrDomainPolicyTCPCaptureRetirementPending
	}
	return m.withExecutionResourcesModeLocked(ctx, p, "xray", action, true)
}

// WithDomainTCPContinuationResources retains up to TWO original detached
// baselines alongside ONE new finite domain execution. Neither the marker nor
// the passed standby can be reconstructed from saved comparison history.
func (m *Manager) WithDomainTCPContinuationResources(ctx context.Context, p Plan, history *updatecheck.ExecutionHistoryAdmission, prior *DomainTCPDetachedStandby, action func(context.Context) error) error {
	if m == nil || ctx == nil || history == nil || prior == nil || prior.self != prior || action == nil || validateDomainTCPProofPlan(p) != nil {
		return ErrDomainTransportRuntime
	}
	deadline, bounded := ctx.Deadline()
	if !bounded || time.Until(deadline) <= 0 || time.Until(deadline) > 2*time.Minute {
		return ErrDomainTransportRuntime
	}
	if err := history.CheckWrite(ctx, 8); err != nil {
		return err
	}
	if err := m.beginOperation(ctx); err != nil {
		return err
	}
	defer m.endOperation()
	if err := history.CheckWrite(ctx, 8); err != nil {
		return err
	}
	guard, _ := ctx.Value(reviewGuardKey{}).(func(context.Context) error)
	if guard == nil {
		return ErrPolicyAdditionUnknown
	}
	if err := guard(ctx); err != nil {
		return err
	}
	return withDomainContinuationAdmission(ctx, m, p, prior, func(admission *domainTCPContinuationAdmission) error {
		if c, err := m.originalDomainPublicationRetry(ctx, p, prior); err != nil {
			return err
		} else if c != nil {
			if c.scope.guard == nil {
				return ErrPolicyAdditionUnknown
			}
			if err := errors.Join(c.scope.guard(ctx), m.checkPlanNetwork(ctx, p)); err != nil {
				return err
			}
			admission.cursor = c
			c.mu.Lock()
			c.admission = admission
			c.mu.Unlock()
			if err := m.writeExecutionOwned(c.scope.root, *c.scope.execution, c.scope); err != nil {
				return domainTCPUnstartedFailure(c, err)
			}
			// Only a zero-resource initial ACK failure is cleared. No callback has
			// run and the SAME live request/guard/plan still owns this scope.
			if err := ctx.Err(); err != nil {
				return err
			}
			c.scope.mu.Lock()
			c.scope.failure = nil
			c.scope.pending = false
			c.scope.mu.Unlock()
			return m.runScopedResourceAction(ctx, p, action, true, false, c.scope)
		}
		return m.withExecutionResourcesSuccessorLocked(ctx, p, "xray", action, true, false, prior, admission)
	})
}
