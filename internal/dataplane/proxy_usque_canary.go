package dataplane

import (
	"context"
	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/ownedfs"
	"github.com/ArtixSx/razvilka/internal/usquediag"
)

// Preflight completes before Start, because a child may connect at startup.
// Missing frozen semantic criteria cannot be repaired by a trace or generic
// SOCKS probe after the process has already started.
func (a *ProxyTunnelAdapter) preflightOwnedUSQUECanary(ctx context.Context, plan RoutePlan, spec ProcessSpec, address string) (RoutePlan, []catalog.Service, error) {
	if err := requireOwnedUSQUEReviewGuard(ctx); err != nil {
		return RoutePlan{}, nil, err
	}
	if a == nil || a.FreshProfile == nil || plan.Adapter != "usque" {
		return RoutePlan{}, nil, errOwnedUSQUECandidate
	}
	transport, err := ownedUSQUECandidateTransport(spec, address)
	if err != nil {
		return RoutePlan{}, nil, err
	}
	root, err := ownedfs.Open(spec.Dir)
	if err != nil {
		return RoutePlan{}, nil, errOwnedUSQUECandidate
	}
	defer root.Close()
	config, err := root.ReadLimited("engine.json", 8<<20)
	if err != nil {
		return RoutePlan{}, nil, errOwnedUSQUECandidate
	}
	defer clear(config)
	if _, err := usquediag.SelectedOwnedUSQUEEndpoint(config, transport); err != nil {
		return RoutePlan{}, nil, errOwnedUSQUECandidate
	}
	semanticPlan := plan
	semanticPlan.Routes = nil
	var services []catalog.Service
	for _, route := range plan.Routes {
		if route.NetworkPolicyRole == "default" {
			// A sealed default cell requests transport readiness. The owned
			// producer's explicit WARP trace proves that separately and emits
			// no catalog ConfirmedRoutes for this cell.
			if _, err := plan.FrozenLAN(); err != nil {
				return RoutePlan{}, nil, err
			}
			continue
		}
		service, err := FrozenProbeService(route)
		if err != nil {
			return RoutePlan{}, nil, err
		}
		services = append(services, service)
		semanticPlan.Routes = append(semanticPlan.Routes, route)
	}
	if _, err := ownedUSQUECandidateServices(ctx, semanticPlan, services); err != nil {
		return RoutePlan{}, nil, err
	}
	return semanticPlan, services, requireOwnedUSQUEReviewGuard(ctx)
}
