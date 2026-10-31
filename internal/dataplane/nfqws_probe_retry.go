package dataplane

import (
	"context"
	"errors"
	"time"
)

// RetryKnownCleanup consumes only this consumer's retained original resource
// and sole-Wait result. It never launches, reacquires runtime/control, adopts a
// disk receipt, records evidence or clears a StrategyLab unknown fence.
func (c *ManagedNFQWSProbeConsumer) RetryKnownCleanup(ctx context.Context) (*ManagedNFQWSProbeCompletion, error) {
	if c == nil || c.self != c || ctx == nil || ctx.Err() != nil {
		return nil, ErrNFQWSManagedProcessUnknown
	}
	c.cleanupMu.Lock()
	defer c.cleanupMu.Unlock()
	c.mu.Lock()
	e := c.active
	c.mu.Unlock()
	if e == nil || e.self != e || !e.open.Load() || e.executing.Load() {
		return nil, ErrNFQWSManagedProcessUnknown
	}
	if !e.entered.Load() {
		// Constructor/socket-only refusal: no COMMON reservation, process intent
		// or rule was reached. Retire only the SAME original held socket/token.
		var completion *ManagedNFQWSProbeCompletion
		err := e.cleanup.WithCurrent(ctx, func() error {
			if err := e.finishKnown(); err != nil {
				return err
			}
			completion = newManagedNFQWSProbeCompletion(e.runtime)
			return nil
		})
		return completion, err
	}
	if e.resource == nil || e.binding == nil || e.processResult == nil && e.processWait == nil {
		return nil, ErrNFQWSManagedProcessUnknown
	}
	// The App still holds the original exclusive lifetime. Its actual tool
	// admission value is carried by ctx; no old canceled forwardctx is revived.
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	ctx = context.WithValue(e.resource.scope.contextWith(ctx), nfqwsProbeExecutionKey{}, e)
	ctx = context.WithValue(ctx, nfqwsProbeCleanupKey{}, e)
	if err := e.cleanupCurrent(ctx); err != nil {
		return nil, err
	}
	if e.processResult == nil {
		lease, err := e.processWait.acknowledge(ctx)
		if err != nil {
			return nil, err
		}
		if !nfqwsScopedLeaseExecutionMatches(lease, e.resource.plan, e.resource.binding) {
			return nil, ErrNFQWSManagedProcessUnknown
		}
		e.processResult = &lease
	}
	if !e.settled.Load() {
		status, err := e.binding.Inspect(ctx, e.resource.plan, e.resource.root)
		if err != nil || status.Unknown || status.Promoted {
			return nil, errors.Join(ErrNFQWSManagedProcessUnknown, err)
		}
		if !status.Removed {
			if err := e.binding.Remove(ctx, e.resource.plan, e.resource.root); err != nil {
				return nil, err
			}
		}
		// SettleRemoved may already have succeeded before process-receipt unlink
		// failed. Re-read the original SAME resource rather than replaying it.
		s := e.resource.scope
		s.mu.Lock()
		removed := false
		for _, r := range s.execution.Resources {
			if r.ID == e.resource.binding.ResourceID {
				removed = r.State == "removed" && r.Phase == "removed"
			}
		}
		s.mu.Unlock()
		if !removed {
			if err := e.resource.SettleRemoved(ctx); err != nil {
				return nil, err
			}
		}
		if err := e.acknowledgeRemoved(ctx, *e.processResult); err != nil {
			return nil, err
		}
	}
	if err := e.finishKnown(); err != nil {
		return nil, err
	}
	return newManagedNFQWSProbeCompletion(e.runtime), nil
}
