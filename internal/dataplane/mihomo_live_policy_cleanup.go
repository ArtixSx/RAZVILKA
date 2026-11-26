package dataplane

import (
	"context"
	"errors"
	"os"

	"github.com/ArtixSx/razvilka/internal/operationgate"
)

func (a *MihomoProbeAdapter) originalLiveProxy(manager *Manager) (*ProxyTunnelAdapter, error) {
	if a == nil || a.self != a || manager == nil || !a.RegisteredWith(manager) {
		return nil, errMihomoLiveMaterial
	}
	a.mu.Lock()
	proxy, original := a.liveProxy, a.liveManager == manager
	a.mu.Unlock()
	if !original || proxy == nil || proxy.mihomoOwner != a || proxy.ID() != "mihomo" || proxy.Table != 207 || proxy.Priority != 31200 || proxy.Interface != "rz-mihomo" {
		return nil, errMihomoLiveMaterial
	}
	return proxy, nil
}

// The caller has already joined original warm children, or supplied the cold
// lane's genuine complete process proof. This function never starts a child,
// examines a PID to signal, adopts a receipt as a warm owner or deletes a TUN.
// Existing exact policy-generation and forwarding owners perform removals.
func (a *ProxyTunnelAdapter) deactivateLivePolicy(ctx context.Context, control *operationgate.ControlEpochReview, cleanup *operationgate.ExclusiveCleanupReview) error {
	if a == nil || a.mihomoOwner == nil || control == nil || cleanup == nil {
		return errMihomoLiveMaterial
	}
	owner := a.mihomoOwner
	owner.mu.Lock()
	manager := owner.liveManager
	owner.mu.Unlock()
	if actual, err := owner.originalLiveProxy(manager); err != nil || actual != a {
		return errMihomoLiveMaterial
	}
	if err := control.CurrentForCleanupOperation(ctx, cleanup); err != nil {
		return err
	}
	state, exists, err := a.loadPolicy()
	if err != nil {
		return err
	}
	if exists {
		if err := a.removeCommittedPolicy(ctx, state); err != nil {
			return err
		}
	} else {
		if _, err := os.Lstat(a.policyBindingPath()); !errors.Is(err, os.ErrNotExist) {
			return ErrProxyPolicyUnknown
		}
		if err := a.removeForwarding(ctx); err != nil {
			return err
		}
	}
	return control.CurrentForCleanupOperation(ctx, cleanup)
}
