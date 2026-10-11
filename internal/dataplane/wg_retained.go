package dataplane

import (
	"context"
	"errors"
	"reflect"
	"sync/atomic"

	"github.com/ArtixSx/razvilka/internal/operationgate"
)

type retainedWGExecution struct {
	self    *retainedWGExecution
	scope   *executionResourceScope
	plan    Plan
	pending bool
	retired bool
	join    func(context.Context) error
}
type wgRetainedOperation struct {
	self    *wgRetainedOperation
	owner   *retainedWGExecution
	cleanup *operationgate.ExclusiveCleanupReview
	forward bool
	open    atomic.Bool
}
type wgRetainedOperationKey struct{}

func (s *executionResourceScope) checkRetainedWGOperation(ctx context.Context, forward bool) error {
	if s == nil || s.wgOwner == nil || !s.retained || s.retainedWGOwner == nil || s.retainedWGOwner.self != s.retainedWGOwner || s.retainedWGOwner.scope != s || wgFiniteContext(ctx) != nil {
		return ErrWGOperationOwner
	}
	op, ok := ctx.Value(wgRetainedOperationKey{}).(*wgRetainedOperation)
	if !ok || op == nil || op.self != op || !op.open.Load() || op.owner != s.retainedWGOwner || op.forward != forward || forward && (s.pending || op.owner.retired) || !forward && op.cleanup == nil {
		return ErrWGOperationOwner
	}
	return nil
}

func (m *WGOperationMaterial) BindSourceReview(ctx context.Context, source *WGListSourceMaterial) error {
	if m == nil || m.self != m || source == nil || source.self != source || source.reader == nil || source.reader.manager != m.manager || source.reader.root != m.root {
		return ErrWGOperationOwner
	}
	if err := m.current(ctx, false); err != nil {
		return err
	}
	if err := source.Current(ctx); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed || m.source != nil && m.source != source {
		return ErrWGOperationOwner
	}
	m.source = source
	return nil
}

func (m *WGOperationMaterial) RetainedOperationContext(ctx context.Context) bool {
	if m == nil || m.self != m || ctx == nil || ctx.Value(wgOperationMaterialKey{}) != m {
		return false
	}
	op, ok := ctx.Value(wgRetainedOperationKey{}).(*wgRetainedOperation)
	return ok && op != nil && op.self == op && op.open.Load() && op.owner != nil && op.owner.self == op.owner && op.owner.scope != nil &&
		op.owner.scope.wgOwner != nil && op.owner.scope.wgOwner.material == m && op.owner.scope.checkRetainedWGOperation(ctx, op.forward) == nil
}

func (m *Manager) retainedWGOwner() *retainedWGExecution {
	m.retainedWGMu.Lock()
	defer m.retainedWGMu.Unlock()
	return m.retainedWG
}
func (m *Manager) retainOriginalWG(ctx context.Context, s *executionResourceScope, join func(context.Context) error) error {
	if s == nil || s.manager != m || s.wgOwner == nil || s.wgOwner.scope != s || s.wgRecords == nil || s.wgOwner.material.source == nil || !s.open || s.retained {
		return ErrWGOperationOwner
	}
	pending := join != nil
	if !pending {
		if s.execution.State != "committed" {
			return ErrWGOperationOwner
		}
		if err := s.wgRecords.current(ctx, true); err != nil {
			return err
		}
		if err := s.wgOwner.check(s.contextWith(ctx), false); err != nil {
			return err
		}
		ref, err := s.wgOwner.adapter.committedWGPolicyReferenceFromOwner(ctx, s.plan)
		if err != nil {
			return err
		}
		s.wgOwner.commonMu.Lock()
		common := s.wgOwner.common[s.wgOwner.adapter.wgPolicyGenerationRoot(ref, "")]
		valid := common != nil && common.current(ctx) == nil && common.status.Complete && !common.status.Unknown && !common.status.Removed && !common.status.Promoted
		s.wgOwner.commonMu.Unlock()
		if !valid {
			return ErrPolicyAdditionReceipt
		}
	}
	o := &retainedWGExecution{scope: s, plan: cloneExecutionResourcePlan(s.plan), pending: pending, join: join}
	o.self = o
	m.retainedWGMu.Lock()
	defer m.retainedWGMu.Unlock()
	if m.retainedWG != nil {
		return ErrWGOperationOwner
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.retained, s.pending, s.retainedWGOwner = true, pending, o
	m.retainedWG = o
	return nil
}

func (a *WARPWireGuardAdapter) committedWGPolicyReferenceFromOwner(ctx context.Context, plan Plan) (warpWGPolicyReference, error) {
	state, owned, err := a.deactivationOwnership(ctx)
	if err != nil || !owned {
		return warpWGPolicyReference{}, errors.Join(ErrWGOperationOwner, err)
	}
	ref, err := a.committedWGPolicyReference(state)
	if err == nil {
		err = a.verifyWGNetworkReferenceScope(plan, ref)
	}
	return ref, err
}

func (o *retainedWGExecution) operation(ctx context.Context, cleanup *operationgate.ExclusiveCleanupReview, forward bool) (context.Context, func(), error) {
	if o == nil || o.self != o || o.scope == nil || o.scope.wgOwner == nil || wgFiniteContext(ctx) != nil || forward && o.pending {
		return nil, nil, ErrWGOperationOwner
	}
	m := o.scope.wgOwner.material
	if forward {
		if err := m.control.Current(ctx); err != nil {
			return nil, nil, err
		}
	} else if err := m.control.CurrentForCleanupOperation(ctx, cleanup); err != nil {
		return nil, nil, err
	}
	op := &wgRetainedOperation{owner: o, cleanup: cleanup, forward: forward}
	op.self = op
	op.open.Store(true)
	ctx = context.WithValue(ctx, wgRetainedOperationKey{}, op)
	ctx = context.WithValue(ctx, wgOperationCleanupKey{}, !forward)
	ctx = WithReviewGuard(ctx, o.scope.guard)
	ctx = o.scope.contextWith(networkPolicyConsumerContext(ctx, o.plan))
	return ctx, func() { op.open.Store(false) }, nil
}

func (m *Manager) CheckRetainedManagedWG(ctx context.Context) error {
	if err := m.beginOperation(ctx); err != nil {
		return err
	}
	defer m.endOperation()
	o := m.retainedWGOwner()
	if o == nil {
		return ErrWGOperationOwner
	}
	c, end, err := o.operation(ctx, nil, true)
	if err != nil {
		return err
	}
	defer end()
	if err := o.scope.wgRecords.current(c, true); err != nil {
		return err
	}
	current, found, err := m.committedLocked()
	if err != nil || !found || current.PlanID != o.plan.PlanID || current.Digest != o.plan.Digest || !reflect.DeepEqual(current.Routes, o.plan.Routes) || !reflect.DeepEqual(current.LAN, o.plan.LAN) {
		return errors.Join(ErrReviewChanged, err)
	}
	a := o.scope.wgOwner.adapter
	state, owned, err := a.deactivationOwnership(c)
	if err != nil || !owned {
		return errors.Join(ErrWGOperationOwner, err)
	}
	ref, err := a.committedWGPolicyReference(state)
	if err != nil || a.verifyWGNetworkReferenceScope(o.plan, ref) != nil {
		return errors.Join(ErrWGOperationOwner, err)
	}
	o.scope.wgOwner.commonMu.Lock()
	p := o.scope.wgOwner.common[a.wgPolicyGenerationRoot(ref, "")]
	valid := p != nil && p.current(c) == nil && reflect.DeepEqual(p.ref, ref) && p.status.Complete && !p.status.Removed && !p.status.Promoted && !p.status.Unknown
	o.scope.wgOwner.commonMu.Unlock()
	if !valid {
		return ErrPolicyAdditionReceipt
	}
	if err := a.healthState(c, o.plan, state, ""); err != nil {
		return err
	}
	return errors.Join(p.current(c), o.scope.wgRecords.current(c, true))
}
func (m *Manager) HasPendingManagedWG() bool {
	o := m.retainedWGOwner()
	return o != nil && o.self == o && o.pending
}
func (m *Manager) JoinPendingManagedWG(ctx context.Context, cleanup *operationgate.ExclusiveCleanupReview) error {
	if err := m.beginOperation(ctx); err != nil {
		return err
	}
	defer m.endOperation()
	o := m.retainedWGOwner()
	if o == nil || !o.pending || o.join == nil {
		return ErrWGOperationOwner
	}
	c, end, err := o.operation(ctx, cleanup, false)
	if err != nil {
		return err
	}
	defer end()
	if err := o.join(c); err != nil {
		return err
	}
	if err := o.scope.close(); err != nil {
		return err
	}
	m.retainedWGMu.Lock()
	defer m.retainedWGMu.Unlock()
	if m.retainedWG != o {
		return ErrWGOperationOwner
	}
	m.retainedWG = nil
	return nil
}
