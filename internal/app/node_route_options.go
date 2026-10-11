package app

import (
	"context"
	"time"

	routecatalog "github.com/ArtixSx/razvilka/internal/routes"
)

func (a *App) appendNodeRouteOptions(ctx context.Context, options []routecatalog.Option) []routecatalog.Option {
	base := append([]routecatalog.Option(nil), options...)
	if a.Nodes == nil || a.Dataplane == nil {
		return base
	}
	engines := map[string]routecatalog.Option{}
	for _, option := range base {
		if !option.Installed {
			continue
		}
		switch option.ID {
		case "sing-box":
			if !a.Dataplane.Capable("sing-box") {
				continue
			}
			option.Ready = true
		case "xray":
			legacy := a.Dataplane.XrayNodeRouteCapable()
			if !legacy && !a.managedXrayNodeSelectionCapable(ctx) || a.nodeHistoryAdmission(ctx, "xray") != nil {
				continue
			}
			// Managed selected TCP prepares its own concrete plan. Selection
			// exposes exact service health, never LAN or Apply readiness.
			option.Ready = legacy
		default:
			continue
		}
		engines[option.ID] = option
	}
	if len(engines) == 0 {
		return base
	}
	profile, err := a.freshNetworkProfile(ctx)
	if err != nil {
		return base
	}
	var generation uint64
	for _, engine := range []string{"sing-box", "xray"} {
		option, enabled := engines[engine]
		if !enabled {
			continue
		}
		// One envelope read per engine, rather than one read per node. Refuse
		// a mixed-generation selector; Apply still rechecks the exact proof.
		snapshot, available, err := a.Nodes.RouteSnapshotForEngine(ctx, engine, profile, time.Now())
		if err != nil || generation != 0 && generation != snapshot.Generation {
			return base
		}
		generation = snapshot.Generation
		name := "Sing-box"
		if engine == "xray" {
			name = "Xray"
		}
		for _, node := range snapshot.Nodes {
			services := available[node.ID]
			if len(services) == 0 || node.Disabled {
				continue
			}
			options = append(options, routecatalog.Option{ID: engine + ":" + node.ID, Name: name + " · " + node.Name,
				Kind: "node", Description: "Точно проверенный узел для выбранного сервиса и текущей сети",
				Installed: true, Configured: true, Running: option.Running, Selectable: true, Ready: option.Ready, Services: services})
		}
		// The managed selected TCP consumer accepts exact node IDs only.
		// Preserve groups solely for the existing scoped executor path.
		if engine == "xray" && !option.Ready {
			continue
		}
		for _, group := range snapshot.Groups {
			services := available[group.ID]
			if len(services) == 0 {
				continue
			}
			mode := "резервная группа"
			if group.Mode == "manual" {
				mode = "выбранный узел"
			}
			options = append(options, routecatalog.Option{ID: engine + ":" + group.ID, Name: name + " · " + group.Name,
				Kind: "node-group", Description: mode + " с возвратом к последнему рабочему узлу",
				Installed: true, Configured: true, Running: option.Running, Selectable: true, Ready: true, Services: services})
		}
	}
	return options
}

// Observe the original completed managed startup registration only. No source
// review, preparation, native observation or operation owner is acquired here.
func (a *App) managedXrayNodeSelectionCapable(ctx context.Context) bool {
	if a == nil || ctx == nil || ctx.Err() != nil || a.Dataplane == nil {
		return false
	}
	a.managedXraySelectedTCPListMu.Lock()
	r := a.managedXraySelectedTCPList
	a.managedXraySelectedTCPListMu.Unlock()
	if r == nil {
		return false
	}
	r.mu.Lock()
	original := r.original() && r.app == a && r.manager == a.Dataplane
	p, manager, adapter := r.policy, r.manager, r.adapter
	r.mu.Unlock()
	if !original || p == nil || adapter == nil || adapter.Configs == nil || adapter.NodeRoutes == nil || adapter.FreshProfile == nil {
		return false
	}
	// Startup fields and the App policy slot are published by this mutex.
	// Never nest policy/runtime locks: runtime Close releases through policy.
	a.managedListPolicyMu.Lock()
	original = a.managedListPolicy == p && p.original() && !p.closed.Load() && p.startupReady && p.startupFailure == nil
	a.managedListPolicyMu.Unlock()
	if !original {
		return false
	}
	p.mu.Lock()
	attached := p.xray == r && !p.xrayClosed && !p.closed.Load()
	p.mu.Unlock()
	if !attached {
		return false
	}
	// This read-only Manager API requires a finite live observation context;
	// the bound adds no command admission or runtime execution permission.
	c, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	registered, err := manager.OriginalXraySelectedTCPDispatcher(c)
	if err != nil || registered != adapter {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.original() && r.app == a && r.manager == manager && r.policy == p && r.adapter == registered &&
		!p.closed.Load() && p.panel.Err() == nil && c.Err() == nil
}
