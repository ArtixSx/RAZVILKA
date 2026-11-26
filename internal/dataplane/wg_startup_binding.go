package dataplane

import "context"

// Bind the SAME retained startup source to the actual registered adapter,
// before the shared policy freezes its participant registry.
func (m *Manager) BindManagedWGCommandTools(ctx context.Context, tools WGCommandTools) error {
	if m == nil || wgFiniteContext(ctx) != nil {
		return ErrWGOperationOwner
	}
	if err := m.beginOperation(ctx); err != nil {
		return err
	}
	defer m.endOperation()
	adapter, found := m.adapter(tools.EngineID)
	a, ok := adapter.(*WARPWireGuardAdapter)
	if !found || !ok || a == nil {
		return ErrWGOperationOwner
	}
	return a.BindWGCommandTools(tools)
}
