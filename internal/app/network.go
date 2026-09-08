package app

import (
	"context"

	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/testlab"
)

// A batch may take minutes. Bind its results before the first request and
// reject them if continuity is lost before the last candidate is cleaned up.
func (a *App) probeRoutesInCurrentNetwork(ctx context.Context, cat catalog.Catalog, services, routes []string) ([]testlab.Result, string, error) {
	profile, err := a.freshNetworkProfile(ctx)
	if err != nil {
		return nil, "", err
	}
	results := a.TestLab.ProbeRoutesUnrecorded(ctx, cat, services, routes, a.RouteProber)
	current, err := a.freshNetworkProfile(ctx)
	if err != nil || current != profile {
		return nil, "", dataplane.ErrExactNodeNetworkChanged
	}
	results, err = a.TestLab.RecordRoutesForProfile(profile, results)
	if err != nil {
		return nil, "", dataplane.ErrExactNodeNetworkChanged
	}
	return results, profile, nil
}
