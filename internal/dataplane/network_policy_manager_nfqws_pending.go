package dataplane

import "context"

// An unknown original Apply retains its exact compensation closure and scope.
// It supplies no forward, replacement or fresh ACTIVE capability.
type pendingNFQWSExecution struct {
	self      *pendingNFQWSExecution
	scope     *executionResourceScope
	execution *nfqws2ActiveExecution
	join      func(context.Context) error
}

func (m *Manager) retainPendingNFQWS(ctx context.Context, s *executionResourceScope, join func(context.Context) error) error {
	e, ok := ctx.Value(nfqws2ActiveExecutionKey{}).(*nfqws2ActiveExecution)
	if !ok || e == nil || e.self != e || e.material == nil || e.material.self != e.material || e.material.manager != m || s != nil && (e.resource == nil || e.resource.scope != s) || join == nil {
		return ErrNFQWSScopedOwner
	}
	m.retainedNFQMu.Lock()
	defer m.retainedNFQMu.Unlock()
	if m.pendingNFQ != nil || m.retainedNFQ != nil {
		return ErrNFQWSScopedOwner
	}
	o := &pendingNFQWSExecution{scope: s, execution: e, join: join}
	o.self = o
	if s != nil {
		s.pending = true
	}
	m.pendingNFQ = o
	return nil
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
	if o == nil || o.self != o || o.scope != nil && !o.scope.pending || o.join == nil || ctx == nil || ctx.Err() != nil || ctx.Value(nfqws2ActiveExecutionKey{}) != o.execution {
		return ErrNFQWSScopedOwner
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
