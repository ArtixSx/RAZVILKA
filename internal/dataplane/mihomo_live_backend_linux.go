//go:build linux

package dataplane

import (
	"context"
	"fmt"
	"net/netip"
)

// The shared socket reader receives PIDs only from these two original opaque
// children. No public PID, receipt or successful boolean supplies this path.
func (r *mihomoLiveResource) backendDisjoint(ctx context.Context, source, pin netip.Addr) error {
	if r == nil || r.self != r || !source.Is4() || !pin.Is4() || !nodeRouterPinInScope(pin, r.definition.Policy.Prefixes) {
		return errMihomoLiveMaterial
	}
	endpoints := map[netip.Addr]bool{}
	for _, address := range r.definition.EndpointAddresses {
		if address == source || address == pin {
			return ErrNodeTransitUnavailable
		}
		endpoints[address] = true
	}
	r.mu.Lock()
	child, sidecar := r.child, r.sidecar
	r.mu.Unlock()
	if child == nil || sidecar == nil {
		return errMihomoLiveMaterial
	}
	if err := r.nativeCurrent(ctx); err != nil {
		return err
	}
	role, err := r.reviewSOCKSUDPListener(ctx)
	if err != nil {
		return err
	}
	if err := inspectOriginalNodeRouterBackendSocketsWithSOCKSUDP(ctx, child.PID(), source, pin, endpoints, r.nativeCurrent, role); err != nil {
		return fmt.Errorf("original Mihomo backend socket inventory: %w", err)
	}
	sidecar.mu.Lock()
	if sidecar.self != sidecar || sidecar.owner != r || sidecar.command == nil || sidecar.command.Process == nil {
		sidecar.mu.Unlock()
		return errMihomoLiveMaterial
	}
	pid := sidecar.command.Process.Pid
	sidecar.mu.Unlock()
	if err := inspectOriginalNodeRouterBackendSockets(ctx, pid, source, pin, endpoints, sidecar.current); err != nil {
		return fmt.Errorf("original Mihomo sidecar socket inventory: %w", err)
	}
	return nil
}
