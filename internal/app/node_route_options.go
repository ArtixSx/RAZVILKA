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
		if option.ID == "sing-box" && a.Dataplane.Capable("sing-box") || option.ID == "xray" && a.Dataplane.XrayNodeRouteCapable() && a.nodeHistoryAdmission(ctx, "xray") == nil {
			engines[option.ID] = option
		}
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
				Installed: true, Configured: true, Running: option.Running, Selectable: true, Ready: true, Services: services})
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
