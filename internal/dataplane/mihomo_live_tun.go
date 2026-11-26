package dataplane

import (
	"context"
	"net/netip"
	"time"
)

func (r *mihomoLiveResource) captureTUN(ctx context.Context) error {
	if r == nil || r.self != r || r.proxy == nil {
		return errMihomoLiveMaterial
	}
	r.mu.Lock()
	sidecar := r.sidecar
	r.mu.Unlock()
	if sidecar == nil {
		return errMihomoLiveMaterial
	}
	prefix, err := netip.ParsePrefix(r.proxy.TunnelCIDR)
	if err != nil || !prefix.Addr().Is4() {
		return errMihomoLiveMaterial
	}
	for {
		index, err := sidecar.tunInterfaceIndex(ctx, false)
		if err == nil {
			request := nodeRouterHTTPSRequest{Interface: r.proxy.Interface, IfIndex: index, Source: prefix.Addr()}
			if err = nodeRouterAssignedSource(ctx, request, nodeRouterHTTPSOptions{}); err == nil {
				r.mu.Lock()
				if r.tunIndex != 0 && r.tunIndex != index {
					r.mu.Unlock()
					return errMihomoLiveMaterial
				}
				r.tunIndex = index
				r.mu.Unlock()
				return nil
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(25 * time.Millisecond):
		}
	}
}
