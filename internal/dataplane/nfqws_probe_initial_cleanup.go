package dataplane

import (
	"context"
	"errors"
	"reflect"
)

// A local association check, not an acknowledgement or cleanup grant. Only the
// still-executing original assembly may complete its already-retained Wait.
func (a *nfqwsExecutionAssembly) initialProbeCleanupWait(ctx context.Context, e *nfqwsProbeExecution) *nfqwsProbeProcessWait {
	if a == nil || a.ctx == nil || ctx == nil || ctx.Err() != nil || e == nil || e.self != e || !e.open.Load() || !e.executing.Load() || e.processResult != nil || e.consumer == nil || e.consumer.self != e.consumer || e.consumer.adapter != a.adapter || a.resource == nil || a.resource != e.resource || a.binding == nil || a.binding != e.binding || a.ctx.Value(nfqwsProbeExecutionKey{}) != e || ctx.Value(nfqwsProbeExecutionKey{}) != e || ctx.Value(nfqwsProbeCleanupKey{}) != e || !reflect.DeepEqual(a.command, e.command) {
		return nil
	}
	if _, bounded := ctx.Deadline(); !bounded {
		return nil
	}
	w := e.processWait
	if w == nil || w.self != w || w.execution != e || w.root == nil || w.command == nil || w.done == nil || !reflect.DeepEqual(w.intent.Command, a.command) || w.intent.LaunchBinding == nil || *w.intent.LaunchBinding != a.resource.binding {
		return nil
	}
	return w
}

// This uses the existing initial-cleanup deadline. No Start, replacement Wait,
// new owner, source revival or evidence publication is possible here. Even a
// completed ACK must leave the caller's original unknown run error intact.
func (a *nfqwsExecutionAssembly) acknowledgeInitialProbeCleanup(ctx context.Context, e *nfqwsProbeExecution) (nfqws2ManagedProcessLease, error) {
	var zero nfqws2ManagedProcessLease
	w := a.initialProbeCleanupWait(ctx, e)
	if w == nil {
		return zero, ErrNFQWSManagedProcessUnknown
	}
	root, resource, binding := w.root, a.resource, a.binding
	if err := e.cleanupCurrent(ctx); err != nil {
		return zero, err
	}
	if a.initialProbeCleanupWait(ctx, e) != w || w.root != root || a.resource != resource || a.binding != binding {
		return zero, ErrNFQWSManagedProcessUnknown
	}
	lease, err := w.acknowledge(ctx)
	if err != nil {
		return zero, err
	}
	if err := e.cleanupCurrent(ctx); err != nil {
		return zero, err
	}
	if a.initialProbeCleanupWait(ctx, e) != w || w.root != root || a.resource != resource || a.binding != binding || !nfqwsScopedLeaseExecutionMatches(lease, resource.Plan(), resource.Binding()) || !lease.Acknowledged || !lease.Receipt.WaitECHILD {
		return zero, ErrNFQWSManagedProcessUnknown
	}
	if err := errors.Join(nfqws2ValidateManagedLease(lease), ctx.Err()); err != nil {
		return zero, err
	}
	return lease, nil
}
