package dataplane

import "context"

// Retain the actual Manager compensation closure, including its CAS undo and
// both final journal writes. A resource-only retirement cannot replace it.
func (m *Manager) retainPendingXray(ctx context.Context, s *executionResourceScope, join func(context.Context) error) error {
	if join == nil {
		return ErrXrayOperationOwner
	}
	if err := m.retainUnknownXray(ctx, s); err != nil {
		return err
	}
	o := m.retainedXrayOwner()
	if o == nil || o.scope != s || !o.pending {
		return ErrXrayOperationOwner
	}
	o.join = join
	return nil
}

func (m *Manager) JoinPendingManagedXraySelectedTCP(ctx context.Context) (*XraySelectedTCPTerminal, error) {
	if err := m.beginOperation(ctx); err != nil {
		return nil, err
	}
	defer m.endOperation()
	o := m.retainedXrayOwner()
	if o == nil || o.self != o || !o.pending || o.join == nil || ctx == nil || ctx.Value(xraySelectedTCPExecutionKey{}) != o.execution {
		return nil, ErrXrayOperationOwner
	}
	c, end, err := o.operation(ctx, o.execution.material.cleanup, false)
	if err != nil {
		return nil, err
	}
	defer end()
	if err := o.recordsCurrent(); err != nil {
		return nil, err
	}
	if err := o.join(c); err != nil {
		return nil, err
	}
	if ok, err := o.execution.verifyRollback(c); err != nil || !ok {
		return nil, ErrPolicyAdditionUnknown
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
