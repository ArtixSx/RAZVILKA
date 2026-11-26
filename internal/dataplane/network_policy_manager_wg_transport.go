package dataplane

import (
	"context"
	"errors"
)

// The observed line is comparison only. Admission comes from the SAME actual
// scope-issued owner and original COMMON publication, followed by complete
// endpoint/routing observations outside the collector boundary.
func (c *NetworkPolicyChecks) WGTransportCheck(ctx context.Context, lan *LANPolicyRuntimePlan, family int, line string) error {
	if c == nil || c.current(ctx) != nil {
		return ErrNetworkPolicyConsumers
	}
	observations, err := c.wgConsumers(ctx, lan)
	if err != nil {
		return err
	}
	matched := 0
	for _, ob := range observations {
		e := ob.ref.Policy.WireGuardEndpoint
		if e == nil || !e.matchesRule(family, line) {
			continue
		}
		if !ob.publication.status.Complete || ob.publication.status.Unknown || ob.publication.status.Removed || ob.publication.status.Promoted || ob.borrowed {
			return ErrPolicyAdditionReceipt
		}
		if err := ob.currentRuntime(ctx); err != nil {
			return err
		}
		if ob.owner.scope.wgRecords == nil {
			return ErrExecutionJournal
		}
		if err := errors.Join(ob.currentFiles(ctx), ob.owner.scope.wgRecords.current(ctx, true)); err != nil {
			return err
		}
		matched++
	}
	if matched != 1 {
		return ErrWGNetworkPolicy
	}
	return c.current(ctx)
}
