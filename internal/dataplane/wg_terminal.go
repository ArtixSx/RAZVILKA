package dataplane

import (
	"context"
	"errors"
	"sync"

	"github.com/ArtixSx/razvilka/internal/operationgate"
)

type WGTerminal struct {
	self    *WGTerminal
	mu      sync.Mutex
	owner   *retainedWGExecution
	stopped *wgStoppedPlanPublication
	closed  bool
}

func (m *Manager) StopRetainedManagedWG(ctx context.Context, cleanup *operationgate.ExclusiveCleanupReview) (*WGTerminal, error) {
	if err := m.beginOperation(ctx); err != nil {
		return nil, err
	}
	defer m.endOperation()
	o := m.retainedWGOwner()
	if o == nil || o.pending {
		return nil, ErrWGOperationOwner
	}
	c, end, err := o.operation(ctx, cleanup, false)
	if err != nil {
		return nil, err
	}
	defer end()
	if err := o.scope.wgRecords.current(c, true); err != nil {
		return nil, err
	}
	if err := o.scope.wgOwner.adapter.Deactivate(c); err != nil {
		return nil, err
	}
	if err := o.scope.wgOwner.adapter.VerifyRuntimeInactive(c); err != nil {
		return nil, err
	}
	gate, found := m.adapter(NetworkPolicyAdapterID)
	if !found {
		return nil, ErrNetworkPolicyConsumers
	}
	deactivator, ok := gate.(RuntimeDeactivator)
	if !ok {
		return nil, ErrNetworkPolicyConsumers
	}
	if err := deactivator.Deactivate(c); err != nil {
		return nil, err
	}
	observer, ok := gate.(RuntimeInactivityObserver)
	if !ok {
		return nil, ErrNetworkPolicyConsumers
	}
	if err := observer.VerifyRuntimeInactive(c); err != nil {
		return nil, err
	}
	if err := o.scope.wgRecords.current(c, true); err != nil {
		return nil, err
	}
	o.scope.mu.Lock()
	o.scope.wgCleanupJoined = true
	o.scope.mu.Unlock()
	o.retired = true
	t := &WGTerminal{owner: o}
	t.self = t
	return t, nil
}
func (t *WGTerminal) current(ctx context.Context) error {
	if t == nil || t.self != t || t.closed || t.owner == nil || t.owner.self != t.owner || !t.owner.retired || t.owner.pending || t.owner.scope == nil || t.owner.scope.manager.retainedWGOwner() != t.owner || wgFiniteContext(ctx) != nil {
		return ErrWGOperationOwner
	}
	s := t.owner.scope
	if !s.open || !s.retained || s.retainedWGOwner != t.owner || s.wgOwner == nil || s.wgRecords == nil {
		return ErrWGOperationOwner
	}
	return s.wgRecords.current(ctx, true)
}
func (t *WGTerminal) ObserveRetired(ctx context.Context, cleanup *operationgate.ExclusiveCleanupReview) error {
	if t == nil || t.owner == nil || t.owner.scope == nil {
		return ErrWGOperationOwner
	}
	m := t.owner.scope.manager
	if err := m.beginOperation(ctx); err != nil {
		return err
	}
	defer m.endOperation()
	if err := t.current(ctx); err != nil {
		return err
	}
	c, end, err := t.owner.operation(ctx, cleanup, false)
	if err != nil {
		return err
	}
	defer end()
	if err := t.owner.scope.wgOwner.adapter.VerifyRuntimeInactive(c); err != nil {
		return err
	}
	gate, found := m.adapter(NetworkPolicyAdapterID)
	if !found {
		return ErrNetworkPolicyConsumers
	}
	observer, ok := gate.(RuntimeInactivityObserver)
	if !ok {
		return ErrNetworkPolicyConsumers
	}
	return errors.Join(observer.VerifyRuntimeInactive(c), t.current(c))
}
func (t *WGTerminal) Close() error {
	if t == nil || t.self != t {
		return ErrWGOperationOwner
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return nil
	}
	if t.owner == nil || !t.owner.retired || t.owner.pending || t.owner.scope == nil || t.owner.scope.manager.retainedWGOwner() != t.owner {
		return ErrWGOperationOwner
	}
	if t.stopped != nil {
		if t.stopped.failure != nil || !t.stopped.files[0].ack || !t.stopped.files[1].ack {
			return ErrExecutionJournal
		}
		if err := t.stopped.close(); err != nil {
			return err
		}
	}
	if err := t.owner.scope.close(); err != nil {
		return err
	}
	m := t.owner.scope.manager
	m.retainedWGMu.Lock()
	defer m.retainedWGMu.Unlock()
	if m.retainedWG != t.owner {
		return ErrWGOperationOwner
	}
	m.retainedWG = nil
	t.closed = true
	return nil
}

func (o *retainedWGExecution) cleanupGuard(ctx context.Context, plan Plan) error {
	if o == nil || o.self != o || o.scope == nil || plan.PlanID != o.plan.PlanID || plan.Digest != o.plan.Digest {
		return ErrWGOperationOwner
	}
	return o.scope.guard(ctx)
}
