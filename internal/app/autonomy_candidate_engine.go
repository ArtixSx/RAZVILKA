package app

import (
	"context"
	"encoding/json"
	"slices"

	"github.com/ArtixSx/razvilka/internal/autonomy"
	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/providerprofile"
)

// AUTO selects the executor required by canonical material, rather than
// consuming XHTTP candidates as unsupported Sing-box peers. Explicit saved
// selections retain their executor. This creates no route or usable proof.
func (a *App) autonomyCandidateEngine(ctx context.Context, p autonomy.Policy, s autonomy.Service, engine, id string) (string, error) {
	if s.ExpectedRoute != "auto" {
		return engine, nil
	}
	selected, err := a.compatibleNodeEngine(ctx, engine, id)
	if err != nil || selected == engine {
		return selected, err
	}
	if !slices.Contains(p.PreferredRoutes, selected) {
		return "", dataplane.ErrExactNodeUnsupported
	}
	return selected, nil
}

func (a *App) compatibleNodeEngine(ctx context.Context, engine, id string) (string, error) {
	if a.Nodes == nil {
		return "", dataplane.ErrExactNodeUnavailable
	}
	selected := engine
	err := a.Nodes.WithSecret(ctx, id, func(raw []byte) error {
		var err error
		selected, err = compatibleAutonomyEngine(raw, engine)
		return err
	})
	if err != nil || selected == engine {
		return selected, err
	}
	installed := false
	for _, option := range a.nodeRouteOptions() {
		if option.ID == selected && option.Installed {
			installed = true
		}
	}
	if !installed {
		return "", dataplane.ErrExactNodeUnsupported
	}
	if _, err := a.nodeCheckerForEngine(selected); err != nil {
		return "", err
	}
	return selected, nil
}

func compatibleAutonomyEngine(raw []byte, engine string) (string, error) {
	var outbound map[string]any
	if json.Unmarshal(raw, &outbound) != nil {
		return "", dataplane.ErrExactNodeUnsupported
	}
	if providerprofile.SingBoxSupportsOutbound(outbound) {
		return engine, nil
	}
	profile, err := providerprofile.VLESSProfileFromOutbound(outbound)
	if err != nil {
		return "", dataplane.ErrExactNodeUnsupported
	}
	compiled, _, err := providerprofile.CompileXrayConfig(profile)
	clear(compiled)
	if err != nil {
		return "", dataplane.ErrExactNodeUnsupported
	}
	return "xray", nil
}
