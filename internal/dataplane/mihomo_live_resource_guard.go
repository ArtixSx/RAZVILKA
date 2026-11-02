package dataplane

import (
	"context"
	"errors"
	"net/netip"
)

// This original startup boundary adds refusals only. It cannot replace any
// retained source, process, control, journal or native service evidence.
func (r *mihomoLiveResource) resourceBoundary(ctx context.Context, host string, address netip.Addr) error {
	if r == nil || r.self != r || r.adapter == nil || r.scope == nil || r.proxy == nil {
		return errMihomoLiveMaterial
	}
	r.adapter.mu.Lock()
	options := r.adapter.liveOptions
	original := r.adapter.liveProxy == r.proxy && r.adapter.liveManager == r.scope.manager
	r.adapter.mu.Unlock()
	if !original || options == nil || options.ResourceGuard == nil {
		return errMihomoLiveMaterial
	}
	return options.ResourceGuard(ctx, r.definition.Plan, host, address)
}

func (r *mihomoLiveResource) resourceContext(ctx context.Context) context.Context {
	return WithNodeResourceGuard(ctx, func(c context.Context, host string, address netip.Addr) error {
		// Read the inherited guard through the original context, never this
		// newly wrapped context; otherwise the guard would recursively call itself.
		return errors.Join(checkNodeResource(ctx, host, address), r.resourceBoundary(c, host, address))
	})
}
