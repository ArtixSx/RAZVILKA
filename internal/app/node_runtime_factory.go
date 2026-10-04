package app

import (
	"context"
	"errors"
	"path/filepath"
	"time"

	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/engineconfig"
	"github.com/ArtixSx/razvilka/internal/nodestore"
)

// NodeRuntimeFactoryOptions contains trusted local owners. It is never decoded
// from a panel request. The Manager supplies transient receipt registration to
// each guarded health operation after this runtime is registered.
type NodeRuntimeFactoryOptions struct {
	Configs      *engineconfig.Manager
	Nodes        *nodestore.Store
	StateRoot    string
	FreshProfile func(context.Context) (string, error)
}

// NewXrayNodeRuntime constructs the ordinary scoped Xray executor and concrete
// router TUN HTTPS verifier. Semantic expectations come from the sealed Plan,
// and optional actual LAN witnesses keep their separate evidence path.
func NewXrayNodeRuntime(options NodeRuntimeFactoryOptions) (*dataplane.ProxyTunnelAdapter, error) {
	if options.Configs == nil || options.Nodes == nil || options.FreshProfile == nil ||
		!filepath.IsAbs(options.StateRoot) || filepath.Clean(options.StateRoot) != options.StateRoot {
		return nil, errors.New("Xray node runtime requires its private store, configs, absolute state root and fresh network owner")
	}
	materialize := func(ctx context.Context, requests []dataplane.NodeRouteRequest, profile string, now time.Time) (dataplane.NodeRouteMaterial, error) {
		if ctx == nil || ctx.Err() != nil || len(requests) == 0 || len(requests) > 64 || profile == "" || now.IsZero() {
			return dataplane.NodeRouteMaterial{}, errors.New("exact current Xray node materialization is required")
		}
		bindings := make([]nodestore.RouteBinding, len(requests))
		for i, request := range requests {
			bindings[i] = nodestore.RouteBinding{ServiceID: request.ServiceID, NodeID: request.NodeID, NetworkProfile: profile,
				Domains: append([]string(nil), request.Domains...), Destinations: append([]string(nil), request.Destinations...)}
		}
		material, err := options.Nodes.MaterializeXray(ctx, bindings, now)
		if err != nil {
			return dataplane.NodeRouteMaterial{}, err
		}
		return dataplane.NodeRouteMaterial{EngineID: "xray", Config: material.Config, EndpointHosts: append([]string(nil), material.EndpointHosts...)}, nil
	}
	adapter, err := dataplane.NewScopedXrayRouterTunnelAdapter(options.Configs, options.StateRoot, materialize)
	if err != nil {
		return nil, err
	}
	adapter.FreshProfile = options.FreshProfile
	return adapter, nil
}
