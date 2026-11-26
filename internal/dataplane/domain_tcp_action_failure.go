package dataplane

import "context"

// Keep the SAME original scope on an exceptional callback, including panic.
// This neither runs another action nor fabricates native terminal evidence.
func domainTCPActionWithCustody(s *executionResourceScope, action func(context.Context) error) (result error) {
	if s.domainSuccessor == nil {
		return action(s.context())
	}
	returned := false
	defer func() {
		if !returned || result != nil {
			s.domainSuccessor.failedCustody.Store(true)
		}
	}()
	result = action(s.context())
	returned = true
	return result
}

// A callback error after genuine Run/join can still have a provable
// restorative footprint. The existing original Retain/finish path performs
// every source/process/receipt/kernel check and keeps the failed outcome.
func (s *executionResourceScope) requestDomainFailureStandby(ctx context.Context) error {
	c := s.domainSuccessor
	if c == nil || c.scope != s || c.original() != nil || c.history == nil || s.domainTCPOwner == nil || s.domainTCPOwner.self != s.domainTCPOwner || s.domainTCPOwner.binding == nil || s.domainTCPOwner.binding.scope != s || c.admission == nil || c.admission.current(c, s.ctx) != nil || !sameNetworkPolicyDependency(c.request, ctx) {
		return ErrPolicyAdditionUnknown
	}
	o := s.domainTCPOwner
	o.mu.Lock()
	existing := o.standbyHistory
	o.mu.Unlock()
	if existing != nil {
		if existing != c.history {
			return ErrPolicyAdditionUnknown
		}
		return nil
	}
	if err := c.history.CheckWrite(ctx, 8); err != nil {
		return err
	}
	return o.RetainStandby(s.contextWith(ctx), c.history)
}
