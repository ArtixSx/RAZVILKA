package dataplane

import (
	"context"
	"errors"
	"github.com/ArtixSx/razvilka/internal/operationgate"
	"sync"
)

// Only joined retirement of the original retained Manager scope issues this
// carrier. Journal data, process observations and copied carriers cannot.
type XraySelectedTCPTerminal struct {
	self     *XraySelectedTCPTerminal
	mu       sync.Mutex
	owner    *retainedXrayExecution
	stopped  *xrayStoppedPlanPublication
	closed   bool
	closeErr error
}
type xraySelectedTCPTerminalKey struct{}

func (m *Manager) StopRetainedManagedXraySelectedTCP(ctx context.Context, cleanup *operationgate.ExclusiveCleanupReview) (*XraySelectedTCPTerminal, error) {
	if err := m.beginOperation(ctx); err != nil {
		return nil, err
	}
	defer m.endOperation()
	m.retainedXrayMu.Lock()
	replacing := m.replacementXray != nil
	m.retainedXrayMu.Unlock()
	if replacing {
		return nil, ErrXrayOperationOwner
	}
	o := m.retainedXrayOwner()
	if o == nil {
		return nil, ErrXrayOperationOwner
	}
	if o.pending {
		return nil, ErrXrayOperationOwner
	} // The original full rollback/CAS join owns unknown Apply.
	c, end, err := o.operation(ctx, cleanup, false)
	if err != nil {
		return nil, err
	}
	defer end()
	if err := o.recordsCurrent(); err != nil {
		return nil, err
	}
	if err := o.execution.rollback(c); err != nil {
		return nil, err
	}
	if ok, err := o.execution.verifyRollback(c); err != nil || !ok {
		return nil, errors.Join(ErrPolicyAdditionUnknown, err)
	}
	gate, found := m.adapter(NetworkPolicyAdapterID)
	if !found || gate != o.execution.gate {
		return nil, ErrNetworkPolicyConsumers
	}
	if err := o.execution.gate.Deactivate(c); err != nil {
		return nil, err
	}
	if err := o.records.current(c, true); err != nil {
		return nil, err
	}
	if err := o.scope.close(); err != nil {
		return nil, err
	}
	m.retainedXrayMu.Lock()
	defer m.retainedXrayMu.Unlock()
	if m.retainedXray != o {
		return nil, ErrXrayOperationOwner
	}
	m.retainedXray = nil
	t := &XraySelectedTCPTerminal{owner: o}
	t.self = t
	return t, nil
}

func (t *XraySelectedTCPTerminal) current(ctx context.Context) error {
	if t == nil || t.self != t || t.closed || t.owner == nil || t.owner.self != t.owner || xraySelectedTCPFinite(ctx) != nil {
		return ErrXrayOperationOwner
	}
	o, e := t.owner, t.owner.execution
	if e == nil || e.self != e || e.resource == nil || e.resource.scope != o.scope || e.checks == nil || e.material.manager.retainedXrayOwner() != nil {
		return ErrXrayOperationOwner
	}
	r, s := e.resource, o.scope
	s.mu.Lock()
	i, err := r.matching()
	valid := err == nil && e.retired && !s.open && !s.observationOpen.Load() && s.closedErr == nil && s.failure == nil && s.retainedXrayOwner == o &&
		validateXraySelectedTCPExecutionResource(s.execution.Resources[i], true) == nil
	s.mu.Unlock()
	if !valid || !r.descriptorsClosed || r.descriptorsErr != nil {
		return ErrXrayOperationOwner
	}
	if r.startACK {
		if !r.stopped || r.child == nil || r.child.Joined(ctx) != nil {
			return ErrPolicyAdditionUnknown
		}
		if err := xraySelectedTCPObserveListenerAbsent(ctx, s.networkIdentity.provider, r.definition.NetworkIdentity, r.definition.Match.Listener); err != nil {
			return err
		}
		if err := xraySelectedTCPObserveConntrackSettled(ctx, s.networkIdentity.provider, r.definition.NetworkIdentity, r.definition.Match); err != nil {
			return err
		}
	} else if r.child != nil || r.selectorUsed || r.versionChild != nil && r.versionChild.Joined(ctx) != nil {
		return ErrPolicyAdditionUnknown
	}
	return o.records.current(ctx, true)
}

// Fresh complete absence uses the original startup collector and checks all
// other adapters. This read never reopens an execution issuer or sends signals.
func (t *XraySelectedTCPTerminal) ObserveRetired(ctx context.Context, cleanup *operationgate.ExclusiveCleanupReview) error {
	if t == nil || t.self != t || cleanup == nil {
		return ErrXrayOperationOwner
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if err := t.current(ctx); err != nil {
		return err
	}
	e := t.owner.execution
	m := e.material.manager
	if err := m.beginOperation(ctx); err != nil {
		return err
	}
	defer m.endOperation()
	return cleanup.WithCurrent(ctx, func() error {
		if err := e.material.control.CurrentForCleanupOperation(ctx, cleanup); err != nil {
			return err
		}
		if err := e.cleanupGuard(ctx, e.plan); err != nil {
			return err
		}
		c := context.WithValue(ctx, xraySelectedTCPTerminalKey{}, t)
		c = context.WithValue(c, xraySelectedTCPExecutionKey{}, e)
		// RetireCheck owns its own provider boundary. Do not nest it inside
		// another read boundary: a waiting writer could deadlock the second
		// read lock while this caller still holds the first one.
		if err := e.checks.RetireCheck(c, e.plan.LAN); err != nil {
			return err
		}
		return e.checks.boundary(c, func(held context.Context) error {
			if owner, err := e.gate.readOwner(); err != nil || owner != nil {
				return errors.Join(ErrNetworkPolicyConsumers, err)
			}
			for pass := 0; pass < 2; pass++ {
				snapshot, err := e.checks.read(held, e.gate.identity.value)
				if err != nil {
					return err
				}
				stock, err := inspectXrayStockOutputQueues(snapshot)
				if err != nil {
					return err
				}
				if err := checkNetworkPolicyInventoryWithStock(snapshot, e.gate.identity.value, nil, LANPolicyXraySelectedTCPMode, nil, stock); err != nil {
					return err
				}
				if err := t.current(held); err != nil {
					return err
				}
			}
			return errors.Join(t.current(held), e.cleanupGuard(held, e.plan), e.material.control.CurrentForCleanupOperation(held, cleanup))
		})
	})
}

func (c *NetworkPolicyChecks) retiredXrayConsumer(ctx context.Context, a *ProxyTunnelAdapter, e *xraySelectedTCPExecution) error {
	if c == nil || e == nil || e.self != e || e.material == nil || e.material.adapter != a || e.checks != c {
		return ErrNetworkPolicyConsumers
	}
	if e.resource == nil {
		if e.replacement == nil && e.preResource != nil {
			return e.preResource.unused(ctx, e)
		}
		p, err := c.xrayReplacement(ctx)
		if err != nil || p.unusedCandidate(ctx, e) != nil {
			return errors.Join(ErrNetworkPolicyConsumers, err)
		}
		return nil
	}
	if t, ok := ctx.Value(xraySelectedTCPTerminalKey{}).(*XraySelectedTCPTerminal); ok {
		if t == nil || t.self != t || t.owner == nil || t.owner.execution != e {
			return ErrXrayOperationOwner
		}
		return t.current(ctx)
	}
	if !e.material.IsCleanupContext(ctx) {
		return ErrXrayOperationOwner
	}
	ok, err := e.verifyRollback(ctx)
	if !ok {
		return errors.Join(ErrNetworkPolicyConsumers, err)
	}
	return err
}

func (t *XraySelectedTCPTerminal) Close() error {
	if t == nil || t.self != t {
		return ErrXrayOperationOwner
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return t.closeErr
	}
	if t.owner == nil || t.owner.execution == nil || !t.owner.execution.resource.descriptorsClosed {
		return ErrXrayOperationOwner
	}
	if t.stopped != nil && (t.stopped.failure != nil || !t.stopped.files[0].ack || !t.stopped.files[1].ack) {
		return ErrExecutionJournal // Keep both original compensation roots open.
	}
	if t.stopped != nil {
		if err := t.stopped.close(); err != nil {
			return err
		}
	}
	t.closed = true
	t.closeErr = t.owner.records.close()
	return t.closeErr
}
