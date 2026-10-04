package dataplane

import (
	"context"
	"errors"
	"path/filepath"
)

// CheckWireGuardProfileReferenceAuthority observes the registered runtime's
// private ownership binding. It never starts, stops, settles or rewrites it.
// Missing journals cannot erase a still-published runtime reference.
func (m *Manager) CheckWireGuardProfileReferenceAuthority(ctx context.Context, committed Plan) error {
	if err := m.CheckExecutionRecovery(ctx); err != nil {
		return err
	}
	m.registryMu.RLock()
	a, ok := m.Adapters["wireguard"].(*WARPWireGuardAdapter)
	m.registryMu.RUnlock()
	if !ok || a == nil || a.ID() != "wireguard" {
		return errors.New("WireGuard reference owner unavailable")
	}
	if err := a.checkWGPolicyOperation(); err != nil {
		return err
	}
	state, owned, err := a.deactivationOwnership(ctx)
	if err != nil {
		return err
	}
	if !owned {
		_, exists, err := readWARPCleanupFile(filepath.Join(a.StateRoot, wgPolicyReferenceFile), policyAdditionMaxBytes)
		if err != nil || exists {
			return errors.Join(err, ErrPolicyAdditionReceipt)
		}
		return ctx.Err()
	}
	selected, err := selectedWireGuardProfile(committed)
	if err != nil || selected == "" || committed.State != "committed" {
		return errors.Join(err, ErrPolicyAdditionUnknown)
	}
	if _, err := a.committedWGPolicyReference(state); err != nil {
		return err
	}
	return ctx.Err()
}
