package dataplane

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"sync/atomic"
	"time"

	"github.com/ArtixSx/razvilka/internal/operationgate"
)

// Only original Manager Apply publishes this owner from its actual scope,
// child and both authored journal FDs. Decoded ACTIVE records cannot issue it.
type retainedXrayExecution struct {
	self      *retainedXrayExecution
	scope     *executionResourceScope
	execution *xraySelectedTCPExecution
	records   *xraySelectedTCPExecutionRecords
	pending   bool
	join      func(context.Context) error
}

type xrayRetainedOperation struct {
	self    *xrayRetainedOperation
	owner   *retainedXrayExecution
	cleanup *operationgate.ExclusiveCleanupReview
	forward bool
	open    atomic.Bool
}
type xrayRetainedOperationKey struct{}

func (s *executionResourceScope) checkRetainedXrayOperation(ctx context.Context, forward bool) error {
	if s == nil || !s.retained || s.retainedXrayOwner == nil || s.retainedXrayOwner.self != s.retainedXrayOwner || s.retainedXrayOwner.scope != s || xraySelectedTCPFinite(ctx) != nil {
		return ErrXrayOperationOwner
	}
	o, ok := ctx.Value(xrayRetainedOperationKey{}).(*xrayRetainedOperation)
	if !ok || o == nil || o.self != o || !o.open.Load() || o.owner != s.retainedXrayOwner || o.forward != forward || forward && (s.pending || o.owner.pending) || !forward && o.cleanup == nil {
		return ErrXrayOperationOwner
	}
	return nil
}

func (s *executionResourceScope) prepareActiveXray(ctx context.Context) error {
	e, ok := ctx.Value(xraySelectedTCPExecutionKey{}).(*xraySelectedTCPExecution)
	if !ok || e == nil || e.self != e || e.resource == nil || e.resource.scope != s || e.node == nil || e.node.current(ctx) != nil {
		return ErrXrayOperationOwner
	}
	if err := e.committedGuard(ctx, e.plan); err != nil {
		return err
	}
	if err := e.health(ctx); err != nil {
		return err
	}
	r := e.resource
	r.mu.Lock()
	defer r.mu.Unlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	i, err := r.matching()
	if err != nil || s.execution.Resources[i].Phase != "applied" || s.execution.Resources[i].XraySelectedTCP.Observation == nil {
		return errors.Join(ErrXrayOperationOwner, err)
	}
	s.execution.Resources[i].State, s.execution.Resources[i].Phase = "active", "active"
	r.active = true
	return nil // Manager's final actual two writers publish this transition.
}

func (m *Manager) retainActiveXray(ctx context.Context, s *executionResourceScope) error {
	return m.retainOriginalXray(ctx, s, false)
}

func (m *Manager) retainUnknownXray(ctx context.Context, s *executionResourceScope) error {
	return m.retainOriginalXray(ctx, s, true)
}

func (m *Manager) retainOriginalXray(ctx context.Context, s *executionResourceScope, pending bool) error {
	e, ok := ctx.Value(xraySelectedTCPExecutionKey{}).(*xraySelectedTCPExecution)
	if !ok || e == nil || e.self != e || e.resource == nil || e.resource.scope != s || s.manager != m || e.material.manager != m || e.resource.records == nil || !pending && s.execution.State != "committed" {
		return ErrXrayOperationOwner
	}
	if !pending {
		if err := e.health(ctx); err != nil {
			return err
		}
		if err := e.resource.records.current(ctx, true); err != nil {
			return err
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.retained || !s.open || len(s.xraySelectedTCP) != 1 {
		return ErrXrayOperationOwner
	}
	if !pending && validateExecutionResources(*s.execution, true) != nil {
		return ErrExecutionJournal
	}
	data, err := json.Marshal(s.execution)
	if err != nil {
		return err
	}
	var detached Execution
	if err := json.Unmarshal(data, &detached); err != nil {
		return err
	}
	o := &retainedXrayExecution{scope: s, execution: e, records: e.resource.records, pending: pending}
	o.self = o
	m.retainedXrayMu.Lock()
	defer m.retainedXrayMu.Unlock()
	if m.retainedXray != nil && (m.replacementXray == nil || m.replacementXray.self != m.replacementXray || m.replacementXray.prior != m.retainedXray || m.replacementXray.candidate != e || m.replacementXray.scope != s) {
		return ErrXrayOperationOwner
	}
	if !pending {
		s.execution = &detached
	} // Pending keeps Manager's exact rollback/CAS closure's original object.
	s.retained, s.pending, s.retainedXrayOwner = true, pending, o
	m.retainedXray = o
	return nil
}

func (o *retainedXrayExecution) recordsCurrent() error {
	if o == nil || o.self != o || o.records == nil || o.scope == nil || o.records.scope != o.scope {
		return ErrExecutionJournal
	}
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	return o.records.current(ctx, !o.pending)
}

func (o *retainedXrayExecution) captureRecords() error { return o.recordsCurrent() }

func (m *Manager) retainedXrayOwner() *retainedXrayExecution {
	m.retainedXrayMu.Lock()
	defer m.retainedXrayMu.Unlock()
	return m.retainedXray
}

func (m *Manager) checkRetainedXrayRecord(record Execution) error {
	if m.hasPendingXrayReplacement() {
		return ErrPolicyAdditionUnknown
	}
	active := false
	for _, resource := range record.Resources {
		active = active || resource.Kind == "xray-selected-tcp" && resource.State == "active"
	}
	if !active {
		return nil
	}
	o := m.retainedXrayOwner()
	if o == nil || o.self != o || o.scope == nil || o.pending {
		return ErrXrayOperationOwner
	}
	o.scope.mu.Lock()
	defer o.scope.mu.Unlock()
	if !o.scope.open || !o.scope.retained || o.scope.retainedXrayOwner != o || !reflect.DeepEqual(*o.scope.execution, record) {
		return ErrXrayOperationOwner
	}
	return o.recordsCurrent()
}

func (o *retainedXrayExecution) operation(ctx context.Context, cleanup *operationgate.ExclusiveCleanupReview, forward bool) (context.Context, func(), error) {
	if o == nil || o.self != o || o.scope == nil || o.execution == nil || o.execution.self != o.execution || o.execution.resource == nil || xraySelectedTCPFinite(ctx) != nil || forward && o.pending {
		return nil, nil, ErrXrayOperationOwner
	}
	m := o.execution.material
	if forward {
		if err := m.control.Current(ctx); err != nil {
			return nil, nil, err
		}
	} else if err := m.control.CurrentForCleanupOperation(ctx, cleanup); err != nil {
		return nil, nil, err
	}
	op := &xrayRetainedOperation{owner: o, cleanup: cleanup, forward: forward}
	op.self = op
	op.open.Store(true)
	ctx = context.WithValue(ctx, xrayRetainedOperationKey{}, op)
	ctx = context.WithValue(ctx, xraySelectedTCPExecutionKey{}, o.execution)
	ctx = context.WithValue(ctx, xrayOperationMaterialKey{}, m)
	ctx = context.WithValue(ctx, xrayOperationOwnerKey{}, o.execution.resource.owner)
	ctx = context.WithValue(ctx, xrayOperationCleanupKey{}, !forward)
	ctx = WithReviewGuard(ctx, o.scope.guard)
	ctx = o.scope.contextWith(networkPolicyConsumerContext(ctx, o.scope.plan))
	return ctx, func() { op.open.Store(false) }, nil
}

func (m *Manager) CheckRetainedManagedXraySelectedTCP(ctx context.Context) error {
	if err := m.beginOperation(ctx); err != nil {
		return err
	}
	defer m.endOperation()
	m.retainedXrayMu.Lock()
	replacing := m.replacementXray != nil
	m.retainedXrayMu.Unlock()
	if replacing {
		return ErrXrayOperationOwner
	}
	o := m.retainedXrayOwner()
	if o == nil {
		return ErrXrayOperationOwner
	}
	c, closeOperation, err := o.operation(ctx, nil, true)
	if err != nil {
		return err
	}
	defer closeOperation()
	if err := m.checkExecutionRecovery(); err != nil {
		return err
	}
	return o.execution.health(c)
}

func (m *Manager) HasPendingManagedXraySelectedTCP() bool {
	if m.hasPendingXrayReplacement() {
		return true
	}
	o := m.retainedXrayOwner()
	return o != nil && o.self == o && o.pending
}
