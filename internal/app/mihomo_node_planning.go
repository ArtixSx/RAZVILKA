package app

import (
	"context"
	"errors"
	"reflect"
	"slices"
	"sync/atomic"

	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/dataplane"
)

// This request-local compiler fact is never installed as the runtime binding.
// General /plan, /apply and AUTO do not receive it. Neither this fact nor the
// resulting preview is service evidence or an execution-resource grant.
type mihomoNodePlanningKey struct{}
type mihomoNodePlanningTicket struct {
	self    *mihomoNodePlanningTicket
	bound   *mihomoNodeBinding
	manager *dataplane.Manager
	ctx     context.Context
	sources []string
	open    atomic.Bool
}

func (p *mihomoNodePlanningTicket) current(ctx context.Context, a *App, routes []dataplane.Route) error {
	if p == nil || p.self != p || !p.open.Load() || ctx == nil || !reflect.TypeOf(ctx).Comparable() || ctx != p.ctx ||
		ctx.Value(mihomoNodePlanningKey{}) != p || p.bound == nil || p.bound.app != a || a == nil ||
		a.Dataplane != p.manager || p.manager == nil || p.bound.node == nil || len(routes) != 1 {
		return dataplane.ErrReviewChanged
	}
	if err := p.bound.current(ctx); err != nil {
		return err
	}
	route, ref := routes[0], p.bound.node.Reference()
	service, err := dataplane.FrozenProbeService(route)
	expected, wantErr := dataplane.FrozenProbeService(dataplane.Route{LogicalServiceID: p.bound.service.ID, ProbeService: &p.bound.service, ProbeURL: p.bound.service.ProbeURL})
	if err != nil || wantErr != nil || ref.EngineID != "mihomo" || route.Selected != ref.Resolved || route.Resolved != "mihomo:"+ref.NodeID ||
		route.ServiceID != p.bound.service.ID || route.LogicalServiceID != p.bound.service.ID ||
		!slices.Equal(route.Sources, p.sources) || !sameMihomoNodePlanningCIDRs(route.CIDRs, p.bound.service.CIDRs) || len(route.Domains) != 0 ||
		!reflect.DeepEqual(service, expected) || !p.manager.MihomoLiveNodePlanSupported(dataplane.Plan{Routes: routes}) {
		return errors.Join(dataplane.ErrReviewChanged, err, wantErr)
	}
	return ctx.Err()
}

func (a *App) buildReviewedMihomoNodePlan(ctx context.Context, before config.Config, cat catalog.Catalog, node *dataplane.NodeDefaultSourceReview, service catalog.Service, sources []string) (dataplane.Plan, error) {
	if ctx == nil || ctx.Err() != nil || ctx.Value(mihomoNodePlanningKey{}) != nil || a == nil || a.Store == nil || a.Dataplane == nil || node == nil {
		return dataplane.Plan{}, dataplane.ErrReviewChanged
	}
	ref := node.Reference()
	preview := nodeRouteConfigForEngineScope(before, "mihomo", service.ID, ref.NodeID, sources)
	if err := mihomoNodeServiceScope(preview, service, sources); err != nil {
		return dataplane.Plan{}, err
	}
	profile, err := a.freshNetworkProfile(ctx)
	if err != nil {
		return dataplane.Plan{}, err
	}
	bound := &mihomoNodeBinding{app: a, store: a.Store, node: node, before: before, catalog: mihomoNodeCatalogClone(cat), service: defaultRouteCloneCatalogService(service), profile: profile}
	bound.self = bound
	p := &mihomoNodePlanningTicket{bound: bound, manager: a.Dataplane, sources: slices.Clone(sources)}
	p.self = p
	p.ctx = context.WithValue(ctx, mihomoNodePlanningKey{}, p)
	p.open.Store(true)
	defer p.open.Store(false)
	if err := bound.current(p.ctx); err != nil {
		return dataplane.Plan{}, err
	}
	plan, err := a.buildDataplanePlanForScopeContext(p.ctx, preview, a.nodeRouteOptions(), changeScopeNode, "")
	if err != nil {
		return dataplane.Plan{}, err
	}
	if err := p.current(p.ctx, a, plan.Routes); err != nil {
		return dataplane.Plan{}, err
	}
	if plan.Revision != before.Revision+1 || plan.NetworkProfileID != profile {
		return dataplane.Plan{}, dataplane.ErrReviewChanged
	}
	return plan, nil
}

// Build sorts prefixes; a reordered catalogue is the same exact destination
// set. Duplicate entries remain unsupported, never compacted into admission.
func sameMihomoNodePlanningCIDRs(actual, expected []string) bool {
	a, b := slices.Clone(actual), slices.Clone(expected)
	slices.Sort(a)
	slices.Sort(b)
	for _, values := range [][]string{a, b} {
		for i := 1; i < len(values); i++ {
			if values[i] == values[i-1] {
				return false
			}
		}
	}
	return len(a) > 0 && slices.Equal(a, b)
}
