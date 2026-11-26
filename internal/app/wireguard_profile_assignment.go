package app

import (
	"context"
	"errors"
	"strings"

	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/dataplane"
	routecatalog "github.com/ArtixSx/razvilka/internal/routes"
)

func (a *App) appendWireGuardRouteOptions(ctx context.Context, options []routecatalog.Option) []routecatalog.Option {
	if a.Dataplane == nil {
		return options
	}
	catalog, err := a.Dataplane.WireGuardProfileCatalog()
	if err != nil {
		return options
	}
	profiles, err := catalog.List(ctx)
	if err != nil || ctx.Err() != nil {
		return options
	}
	installed := false
	for _, option := range options {
		if option.ID == "wireguard" {
			installed = option.Installed
		}
	}
	for _, profile := range profiles {
		options = append(options, routecatalog.Option{ID: "wireguard:" + profile.ID, Name: "WireGuard · " + profile.Name,
			Kind: "wireguard-profile", Description: "Импортированный профиль. Проверка и применение выполняются отдельно.",
			Installed: installed, Configured: true, Selectable: true, WireGuardProfileRevision: profile.Revision})
	}
	return options
}

func (a *App) bindNamedWireGuardService(ctx context.Context, id, route string, state config.ServiceState, revision *uint64, expected string) (config.ServiceState, error) {
	if revision == nil || a.Dataplane == nil {
		return state, config.ErrWireGuardProfileBinding
	}
	current := a.Store.Get().Services[id]
	if !state.Enabled && selectedRoute(current) == route {
		// Withdrawing retained intent must remain possible if its component or
		// profile disappeared. This cannot create a new live profile binding.
		if expected != "" && expected != current.WireGuardProfileRevision ||
			state.WireGuardProfileRevision != "" && state.WireGuardProfileRevision != current.WireGuardProfileRevision {
			return state, config.ErrWireGuardProfileBinding
		}
		state.WireGuardProfileRevision = current.WireGuardProfileRevision
		return state, ctx.Err()
	}
	if _, err := dataplane.FrozenWireGuardProfileRevision(dataplane.Route{Selected: route, Resolved: route, WireGuardProfileRevision: expected}); err != nil ||
		state.WireGuardProfileRevision != "" && state.WireGuardProfileRevision != expected {
		return state, config.ErrWireGuardProfileBinding
	}
	if err := a.checkNamedWireGuardRevision(ctx, route, expected); err != nil {
		return state, err
	}
	state.WireGuardProfileRevision = expected
	return state, nil
}

func (a *App) checkNamedWireGuardRevision(ctx context.Context, route, expected string) error {
	if _, err := dataplane.FrozenWireGuardProfileRevision(dataplane.Route{Selected: route, Resolved: route, WireGuardProfileRevision: expected}); err != nil || a.Dataplane == nil {
		return config.ErrWireGuardProfileBinding
	}
	catalog, err := a.Dataplane.WireGuardProfileCatalog()
	if err != nil {
		return err
	}
	profile, err := catalog.Get(ctx, strings.TrimPrefix(route, "wireguard:"))
	if err != nil || profile.Public().Revision != expected {
		return errors.Join(err, dataplane.ErrWireGuardProfileRevision)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return nil
}
