package dataplane

import (
	"context"
	"errors"
	"reflect"
)

// Only Manager.ProbeCandidate installs this private adapter view. The actual
// registered adapter retains no generic Canary method or second runtime.
type nfqwsProbeCanaryAdapter struct {
	Adapter
	execution *nfqwsProbeExecution
}

func nfqwsProbeAdapter(ctx context.Context, adapter Adapter, plan Plan) (Adapter, CanaryAdapter, bool, error) {
	if ctx == nil || ctx.Value(nfqwsProbeExecutionKey{}) == nil {
		return adapter, nil, false, nil
	}
	e, ok := ctx.Value(nfqwsProbeExecutionKey{}).(*nfqwsProbeExecution)
	if !ok || e == nil || e.self != e || e.consumer == nil || adapter != e.consumer.adapter || !reflect.DeepEqual(plan, e.plan) {
		return nil, nil, true, ErrNFQWSScopedOwner
	}
	if err := e.current(ctx); err != nil {
		return nil, nil, true, err
	}
	facade := &nfqwsProbeCanaryAdapter{Adapter: adapter, execution: e}
	return facade, facade, true, nil
}

func (a *nfqwsProbeCanaryAdapter) phase(ctx context.Context, p Plan, root string) error {
	if a == nil || a.execution == nil || root == "" || !reflect.DeepEqual(p, a.execution.plan) {
		return ErrNFQWSScopedOwner
	}
	return a.execution.current(ctx)
}
func (a *nfqwsProbeCanaryAdapter) Snapshot(c context.Context, p Plan, r string) error {
	return a.phase(c, p, r)
}
func (a *nfqwsProbeCanaryAdapter) Stage(c context.Context, p Plan, r string) error {
	return a.phase(c, p, r)
}
func (a *nfqwsProbeCanaryAdapter) Validate(c context.Context, p Plan, r string) error {
	return a.phase(c, p, r)
}

func (a *nfqwsProbeCanaryAdapter) Canary(ctx context.Context, plan RoutePlan, root string) error {
	e := a.execution
	if e == nil || !reflect.DeepEqual(plan, e.plan.RoutePlanFor("nfqws2")) {
		return ErrNFQWSScopedOwner
	}
	if err := e.current(ctx); err != nil {
		return err
	}
	c := e.consumer
	assembly, err := newNFQWSExecutionAssembly(ctx, c.adapter, e.command, e.spec, nil, nfqwsExecutionRuntime{
		Runner: c.gate.Binding.Runtime.Runner, Tools: PolicyEffectTools{IPTables: c.inventory.reader.IPTables, IP6Tables: c.inventory.reader.IP6Tables},
		VerifyLAN: func(c context.Context, lan *LANPolicyRuntimePlan) error {
			if lan != nil {
				return ErrNFQWSScopedOwner
			}
			return e.operationGuard(c)
		},
		AdditionalReadback: func(c context.Context, p *NFQWSScopedPlan) error {
			if p == nil || p.spec.Probe == nil || !reflect.DeepEqual(p.spec, e.spec) {
				return ErrNFQWSScopedOwner
			}
			return e.operationGuard(c)
		},
	})
	if err != nil {
		return err
	}
	e.resource, e.binding = assembly.resource, assembly.binding
	typed, err := NewTypedNFQWSScopedBinding(c.provider, &c.inventory, *assembly.binding)
	if err != nil {
		return err
	}
	assembly.binding = typed
	e.binding = typed
	err = assembly.run(e.observeService)
	if !e.settled.Load() {
		return errors.Join(ErrNFQWSManagedProcessUnknown, err)
	}
	return err
}

// Bound to the SAME synchronous assembly and actual ACK, never callable from
// a persisted removed resource. Only this completion can release socket/runtime.
func (e *nfqwsProbeExecution) acknowledgeRemoved(ctx context.Context, lease nfqws2ManagedProcessLease) error {
	if e == nil || e.self != e || e.resource == nil || e.binding == nil || !nfqwsScopedLeaseExecutionMatches(lease, e.resource.plan, e.resource.binding) || !lease.Acknowledged || !lease.Receipt.WaitECHILD || nfqws2ValidateManagedLease(lease) != nil {
		return ErrNFQWSScopedOwner
	}
	if err := e.cleanupCurrent(ctx); err != nil {
		return err
	}
	e.resource.scope.mu.Lock()
	removed := false
	for _, record := range e.resource.scope.execution.Resources {
		if record.ID == e.resource.binding.ResourceID {
			removed = record.State == "removed" && record.Phase == "removed" && record.NFQWS != nil && reflect.DeepEqual(record.NFQWS.Spec, e.spec)
		}
	}
	e.resource.scope.mu.Unlock()
	if !removed {
		return ErrNFQWSScopedOwner
	}
	if err := e.retireProcessReceipt(ctx, lease); err != nil {
		return err
	}
	e.settled.Store(true)
	return nil
}
