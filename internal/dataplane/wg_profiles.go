package dataplane

import (
	"context"
	"errors"
	"strings"

	"github.com/ArtixSx/razvilka/internal/wireguardprofile"
)

type WireGuardProfileProvider interface {
	Get(context.Context, string) (wireguardprofile.Profile, error)
}

// The app catalog and runtime consume the same explicitly registered owner.
// Observing an API never creates a second store or discovers a private path.
type WireGuardProfileCatalog interface {
	WireGuardProfileProvider
	List(context.Context) ([]wireguardprofile.Metadata, error)
	Put(context.Context, string, string, string, string) (wireguardprofile.Metadata, error)
	Delete(context.Context, string, string) error
}

func (m *Manager) WireGuardProfileCatalog() (WireGuardProfileCatalog, error) {
	if m == nil {
		return nil, errors.New("named WireGuard profile runtime is unavailable")
	}
	m.registryMu.RLock()
	defer m.registryMu.RUnlock()
	adapter, ok := m.Adapters["wireguard"].(*WARPWireGuardAdapter)
	if !ok || adapter == nil || adapter.ID() != "wireguard" {
		return nil, errors.New("named WireGuard profile runtime is unavailable")
	}
	catalog, ok := adapter.Profiles.(WireGuardProfileCatalog)
	if !ok || catalog == nil {
		return nil, errors.New("named WireGuard profile catalog is unavailable")
	}
	return catalog, nil
}

func selectedWireGuardProfile(plan Plan) (string, error) {
	selected := ""
	for _, route := range plan.Routes {
		if adapterID(route.Resolved) != "wireguard" {
			continue
		}
		id := "main"
		if route.Resolved != "wireguard" {
			id = strings.TrimPrefix(route.Resolved, "wireguard:")
			if !wireguardprofile.ValidID(id) {
				return "", errors.New("invalid selected WireGuard profile")
			}
		}
		if selected != "" && selected != id {
			return "", errors.New("one WireGuard runtime cannot activate multiple different profiles in the same plan")
		}
		selected = id
	}
	return selected, nil
}

func (a *WARPWireGuardAdapter) verifyNamedProfile(ctx context.Context, snapshot warpWGSnapshot) error {
	if snapshot.NamedProfileID == "" {
		return nil
	}
	if a.Profiles == nil {
		return errors.New("named WireGuard profile provider is unavailable")
	}
	p, err := a.Profiles.Get(ctx, snapshot.NamedProfileID)
	if err != nil {
		return err
	}
	if p.Public().Revision != snapshot.NamedProfileRevision || p.Config() != string(snapshot.Profile) {
		return errors.New("selected WireGuard profile changed after snapshot")
	}
	return nil
}
