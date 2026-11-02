package app

import (
	"context"
	"errors"
	"net/netip"
	"reflect"

	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/systemprobe"
)

// ConfigureMihomoLive binds only original startup owners. Installed binaries,
// saved health and a successful finite probe never select or start this path.
func (a *App) ConfigureMihomoLive(ctx context.Context) error {
	if a == nil || a.Store == nil || a.EngineConfigs == nil || a.Nodes == nil || a.Dataplane == nil || a.SelfUpdateFiles == nil || a.ExecutionHistory == nil {
		return dataplane.ErrReviewChanged
	}
	a.mihomoProbe.mu.Lock()
	adapter, manager, components := a.mihomoProbe.adapter, a.mihomoProbe.manager, a.mihomoProbe.components
	a.mihomoProbe.mu.Unlock()
	if adapter == nil || manager != a.Dataplane || components != a.Components || !adapter.RegisteredWith(manager) {
		return dataplane.ErrReviewChanged
	}
	store, nodes, configs := a.Store, a.Nodes, a.EngineConfigs
	fresh := a.FreshProfile
	if fresh == nil {
		fresh = func(c context.Context) (string, error) {
			profile, err := systemprobe.FreshWANProfile(c)
			return profile.ID, err
		}
	}
	options := dataplane.MihomoLiveOptions{Manager: manager, Configs: configs, Nodes: nodes, Gate: &a.Operations, ControlRoot: a.SelfUpdateFiles.ControlRoot, History: a.ExecutionHistory, FreshProfile: fresh, SidecarKind: a.ProxySidecarBoot}
	options.ResourceGuard = func(c context.Context, plan dataplane.Plan, host string, address netip.Addr) error {
		if a.Store != store || a.Nodes != nodes || a.EngineConfigs != configs || a.Dataplane != manager || a.Components != components || !adapter.RegisteredWith(manager) || len(plan.Routes) != 1 {
			return dataplane.ErrReviewChanged
		}
		cfg := store.Get()
		if cfg.Revision != plan.Revision {
			return dataplane.ErrReviewChanged
		}
		network, err := fresh(c)
		if err != nil || network != plan.NetworkProfileID {
			return errors.Join(dataplane.ErrReviewChanged, err)
		}
		route := plan.Routes[0]
		for _, service := range a.catalogSnapshot().Services {
			if service.ID != route.LogicalServiceID {
				continue
			}
			frozen, err := dataplane.FrozenProbeService(dataplane.Route{LogicalServiceID: service.ID, ProbeService: &service, ProbeURL: service.ProbeURL})
			actual, actualErr := dataplane.FrozenProbeService(route)
			if err != nil || actualErr != nil || !reflect.DeepEqual(frozen, actual) {
				return dataplane.ErrReviewChanged
			}
			return a.nodeResourceExclusionAdmission(c, cfg, service, host, address)
		}
		return dataplane.ErrReviewChanged
	}
	return adapter.ConfigureLiveRuntime(ctx, options)
}
