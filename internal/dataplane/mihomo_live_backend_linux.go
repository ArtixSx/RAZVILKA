//go:build linux

package dataplane

import (
	"context"
	"fmt"
	"net/netip"

	"github.com/ArtixSx/razvilka/internal/components"
	"github.com/ArtixSx/razvilka/internal/netidentity"
)

// The shared socket reader receives PIDs only from these two original opaque
// children. No public PID, receipt or successful boolean supplies this path.
func (r *mihomoLiveResource) backendDisjoint(ctx context.Context, source, pin netip.Addr) error {
	if r == nil || r.self != r || !source.Is4() || !pin.Is4() || !nodeRouterPinInScope(pin, r.definition.Policy.Prefixes) {
		return errMihomoLiveMaterial
	}
	child, err := r.nativeReadOwner(ctx)
	if err != nil {
		return err
	}
	return r.adapter.provider.WithCurrent(ctx, func(networkCtx context.Context, current netidentity.Identity) error {
		if current != r.definition.NetworkIdentity {
			return errMihomoLiveMaterial
		}
		return child.WithReadObservation(networkCtx, func(held context.Context, view *components.MihomoLiveObservation) error {
			if !view.BoundTo(child, r.source) {
				return errMihomoLiveMaterial
			}
			return r.backendDisjointInReadView(held, source, pin, view, current)
		})
	})
}

func (r *mihomoLiveResource) backendDisjointInReadView(ctx context.Context, source, pin netip.Addr, view *components.MihomoLiveObservation, current netidentity.Identity) error {
	if r == nil || r.self != r || !source.Is4() || !pin.Is4() || !nodeRouterPinInScope(pin, r.definition.Policy.Prefixes) || current != r.definition.NetworkIdentity {
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
	readCurrent := func(c context.Context) error { return r.nativeCurrentWithReadView(c, view, current) }
	if err := readCurrent(ctx); err != nil {
		return err
	}
	role, err := r.reviewSOCKSUDPListenerRead(ctx, view)
	if err != nil {
		return err
	}
	if err := inspectOriginalNodeRouterBackendSocketsWithSOCKSUDP(ctx, child.PID(), source, pin, endpoints, readCurrent, role); err != nil {
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
