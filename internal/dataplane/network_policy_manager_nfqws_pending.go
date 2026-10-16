package dataplane

import (
	"context"
	"errors"
)

// Minted by the actual Manager immediately after creating its registrar, before
// entering Activate. A resource does not exist yet at that boundary. This is
// only an original-owner witness: it supplies no forward or cleanup permission.
type nfqwsPendingScopeClaim struct {
	self      *nfqwsPendingScopeClaim
	manager   *Manager
	scope     *executionResourceScope
	execution *nfqws2ActiveExecution
}

func (m *Manager) newNFQWSExecutionResourceScope(ctx context.Context, plan Plan, adapter string, execution *Execution, root string) (*executionResourceScope, *nfqwsPendingScopeClaim, error) {
	s, err := m.newExecutionResourceScope(ctx, plan, adapter, execution, root)
	if err != nil {
		return nil, nil, err
	}
	if ctx.Value(nfqws2ActiveExecutionKey{}) == nil {
		return s, nil, nil // Existing legacy package flow has no scoped participant.
	}
	e, _ := ctx.Value(nfqws2ActiveExecutionKey{}).(*nfqws2ActiveExecution)
	c := &nfqwsPendingScopeClaim{manager: m, scope: s, execution: e}
	c.self = c
	if e == nil || e.self != e || e.material == nil || e.material.self != e.material || e.material.manager != m || e.material.execution != e || !e.material.executionBound ||
		s.manager != m || s.adapterOwner != e.material.adapter || s.adapter != "nfqws2" || !nfqws2ActiveSamePlan(e.plan, s.plan) {
		// The actual Manager still owns this freshly created registrar. A failed
		// association may only park it as blocked; never publish a join grant.
		return s, c, ErrNFQWSScopedOwner
	}
	return s, c, nil
}

func (c *nfqwsPendingScopeClaim) original(m *Manager, e *nfqws2ActiveExecution, s *executionResourceScope) bool {
	return c != nil && c.self == c && c.manager == m && c.execution == e && c.scope == s
}

// An unknown original Apply retains its exact compensation closure and scope.
// It supplies no forward, replacement or fresh ACTIVE capability.
type pendingNFQWSExecution struct {
	self      *pendingNFQWSExecution
	scope     *executionResourceScope
	execution *nfqws2ActiveExecution
	join      func(context.Context) error
	claim     *nfqwsPendingScopeClaim
	blocked   error
	conflict  *pendingNFQWSExecution // Retain both originals; never choose one by DTO.
}

func (m *Manager) retainPendingNFQWS(ctx context.Context, s *executionResourceScope, join func(context.Context) error, claim *nfqwsPendingScopeClaim) error {
	if ctx == nil {
		return m.parkFailedNFQWSScope(claim, join, ErrNFQWSScopedOwner)
	}
	e, ok := ctx.Value(nfqws2ActiveExecutionKey{}).(*nfqws2ActiveExecution)
	if !ok || e == nil || e.self != e || e.material == nil || e.material.self != e.material || e.material.manager != m || e.material.execution != e || !e.material.executionBound || join == nil ||
		s != nil && !claim.original(m, e, s) || s == nil && claim != nil {
		return m.parkFailedNFQWSScope(claim, join, ErrNFQWSScopedOwner)
	}
	var blocked error
	if s != nil {
		s.mu.Lock()
		if !s.open || s.manager != m || s.adapterOwner != e.material.adapter || !nfqws2ActiveSamePlan(e.plan, s.plan) || e.resource != nil && e.resource.scope != s {
			blocked = ErrNFQWSScopedOwner
		}
		s.pending = true
		s.mu.Unlock()
	}
	return m.parkPendingNFQWS(&pendingNFQWSExecution{scope: s, execution: e, join: join, claim: claim, blocked: blocked})
}

// Even unexpected structural drift must not make a failed retain release the
// original registrar. The immutable Manager claim can park it, but cannot make
// that blocked owner joinable. In particular a copied claim grants nothing.
func (m *Manager) parkFailedNFQWSScope(claim *nfqwsPendingScopeClaim, join func(context.Context) error, cause error) error {
	if claim == nil || !claim.original(m, claim.execution, claim.scope) || claim.scope == nil || join == nil {
		return ErrNFQWSScopedOwner
	}
	claim.scope.mu.Lock()
	claim.scope.pending = true
	claim.scope.mu.Unlock()
	return m.parkPendingNFQWS(&pendingNFQWSExecution{scope: claim.scope, execution: claim.execution, join: join, claim: claim, blocked: errors.Join(ErrNFQWSScopedOwner, cause)})
}

func (m *Manager) parkPendingNFQWS(o *pendingNFQWSExecution) error {
	m.retainedNFQMu.Lock()
	defer m.retainedNFQMu.Unlock()
	o.self = o
	if m.pendingNFQ != nil {
		o.blocked = errors.Join(o.blocked, ErrNFQWSScopedOwner)
		o.conflict, m.pendingNFQ.conflict = m.pendingNFQ.conflict, o
		return ErrNFQWSScopedOwner
	}
	if m.retainedNFQ != nil {
		o.blocked = errors.Join(o.blocked, ErrNFQWSScopedOwner)
	}
	m.pendingNFQ = o
	return o.blocked
}

// HasPendingManagedNFQWS is only an owner-presence comparison. It cannot grant
// cleanup, adopt a decoded record, or release the original App operation.
func (m *Manager) HasPendingManagedNFQWS() bool {
	if m == nil {
		return false
	}
	m.retainedNFQMu.Lock()
	defer m.retainedNFQMu.Unlock()
	return m.pendingNFQ != nil
}

// JoinPendingManagedNFQWS requires values from the SAME still-held original
// App Apply. The App keeps that operation and all source/tool owners until the
// original compensation proves both retirement and BOTH journal outcomes.
func (m *Manager) JoinPendingManagedNFQWS(ctx context.Context) error {
	if err := m.beginOperation(ctx); err != nil {
		return err
	}
	defer m.endOperation()
	m.retainedNFQMu.Lock()
	o := m.pendingNFQ
	m.retainedNFQMu.Unlock()
	if o == nil || o.self != o || o.blocked != nil || o.conflict != nil || o.join == nil || ctx == nil || ctx.Err() != nil || ctx.Value(nfqws2ActiveExecutionKey{}) != o.execution {
		return ErrNFQWSScopedOwner
	}
	if o.scope != nil {
		o.scope.mu.Lock()
		pending := o.scope.pending && o.claim.original(m, o.execution, o.scope)
		err := o.scope.checkOriginalOwner(ctx, nil, false, true)
		o.scope.mu.Unlock()
		if !pending || err != nil || o.execution.resource != nil && o.execution.resource.scope != o.scope {
			return errors.Join(ErrNFQWSScopedOwner, err)
		}
	}
	if _, ok := ctx.Deadline(); !ok {
		return ErrNFQWSScopedOwner
	}
	ctx = networkPolicyConsumerContext(ctx, o.execution.plan)
	if o.scope != nil {
		ctx = o.scope.contextWith(ctx)
	}
	if err := o.execution.pendingCleanupCurrent(ctx); err != nil {
		return err
	}
	if err := o.join(ctx); err != nil {
		return err
	}
	if o.scope != nil {
		if err := o.scope.close(); err != nil {
			return err
		}
	}
	m.retainedNFQMu.Lock()
	defer m.retainedNFQMu.Unlock()
	if m.pendingNFQ != o {
		return ErrNFQWSScopedOwner
	}
	m.pendingNFQ = nil
	return nil
}
