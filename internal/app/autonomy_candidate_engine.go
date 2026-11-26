package app

import (
	"context"
	"encoding/json"
	"slices"

	"github.com/ArtixSx/razvilka/internal/autonomy"
	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/providerprofile"
)

// Select the search executor separately from the engine of an applied route.
// Older consent with sources and neither proxy engine still uses Sing-box.
// An explicitly ordered pair can use the other engine if its checker is the
// only one registered, or if it is installed while the first is absent.
// Every candidate still needs a compatible exact checker and its own proof.
func (a *App) autonomySearchEngine(cfg config.Config, p autonomy.Policy, s autonomy.Service) string {
	if s.ExpectedRoute != "auto" || !slices.Contains(p.PreferredRoutes, "xray") {
		return autonomyNodeEngine(s.ExpectedRoute)
	}
	if cfg.NetworkPolicy != nil || !slices.Contains(p.PreferredRoutes, "sing-box") {
		return "xray"
	}
	first, second := "sing-box", "xray"
	if slices.Index(p.PreferredRoutes, second) < slices.Index(p.PreferredRoutes, first) {
		first, second = second, first
	}
	_, firstErr := a.nodeCheckerForEngine(first)
	_, secondErr := a.nodeCheckerForEngine(second)
	if firstErr != nil && secondErr == nil {
		return second
	}
	if firstErr == nil && secondErr != nil {
		return first
	}
	if !a.autonomyNodeEngineInstalled(first) && a.autonomyNodeEngineInstalled(second) {
		return second
	}
	return first
}

// AUTO selects the executor required by canonical material, rather than
// consuming XHTTP candidates as unsupported Sing-box peers. Explicit saved
// selections retain their executor. This creates no route or usable proof.
func (a *App) autonomyCandidateEngine(ctx context.Context, p autonomy.Policy, s autonomy.Service, engine, id string) (string, error) {
	selected, err := a.autonomyCandidateRequirement(ctx, p, s, engine, id)
	if err != nil || selected == engine {
		return selected, err
	}
	return a.installedAlternateNodeEngine(selected)
}

func (a *App) autonomyAlternateCandidateEngine(ctx context.Context, cfg config.Config, p autonomy.Policy, s autonomy.Service, engine, id string) string {
	if s.ExpectedRoute != "auto" {
		return ""
	}
	other := "sing-box"
	if engine == "sing-box" {
		other = "xray"
	}
	if !slices.Contains(p.PreferredRoutes, other) || a.autonomyCapabilityRefusal(cfg, s.ID, other+":node-") != nil {
		return ""
	}
	if _, err := a.installedAlternateNodeEngine(other); err != nil {
		return ""
	}
	if compatible, err := a.requiredNodeEngine(ctx, other, id); err != nil || compatible != other {
		return ""
	}
	return other
}

func (a *App) autonomyCandidateRequirement(ctx context.Context, p autonomy.Policy, s autonomy.Service, engine, id string) (string, error) {
	if s.ExpectedRoute != "auto" {
		return engine, nil
	}
	selected, err := a.requiredNodeEngine(ctx, engine, id)
	if err != nil || selected == engine {
		return selected, err
	}
	if !slices.Contains(p.PreferredRoutes, selected) {
		return "", dataplane.ErrExactNodeUnsupported
	}
	return selected, nil
}

func (a *App) compatibleNodeEngine(ctx context.Context, engine, id string) (string, error) {
	selected, err := a.requiredNodeEngine(ctx, engine, id)
	if err != nil || selected == engine {
		return selected, err
	}
	return a.installedAlternateNodeEngine(selected)
}

func (a *App) requiredNodeEngine(ctx context.Context, engine, id string) (string, error) {
	if a.Nodes == nil {
		return "", dataplane.ErrExactNodeUnavailable
	}
	selected := engine
	err := a.Nodes.WithSecret(ctx, id, func(raw []byte) error {
		var err error
		selected, err = compatibleAutonomyEngine(raw, engine)
		return err
	})
	return selected, err
}

func (a *App) installedAlternateNodeEngine(selected string) (string, error) {
	if !a.autonomyNodeEngineInstalled(selected) {
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
	singBox := providerprofile.SingBoxSupportsOutbound(outbound)
	if engine == "sing-box" && singBox {
		return "sing-box", nil
	}
	profile, err := providerprofile.VLESSProfileFromOutbound(outbound)
	if err == nil {
		compiled, _, compileErr := providerprofile.CompileXrayConfig(profile)
		clear(compiled)
		if compileErr == nil {
			return "xray", nil
		}
	}
	if singBox {
		return "sing-box", nil
	}
	return "", dataplane.ErrExactNodeUnsupported
}
