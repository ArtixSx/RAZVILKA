package app

import (
	"context"
	"errors"

	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/netidentity"
)

// Private startup assembly seam. Only the original Manager's concrete review is
// supplied by production; tests model lifetime revocation without native effects.
type managedListInactivitySources interface {
	Sources(context.Context) (*netidentity.Provider, *dataplane.BackendInventory, error)
	CheckCurrent(context.Context) error
}

func selectManagedListInactivitySources(ctx context.Context, lookup func() (managedListInactivitySources, error), createProvider func(context.Context) (*netidentity.Provider, error)) (managedListInactivitySources, *netidentity.Provider, *dataplane.BackendInventory, error) {
	r, err := lookup()
	if err == nil {
		if r == nil {
			return nil, nil, nil, dataplane.ErrRuntimeInactivity
		}
		provider, inventory, err := r.Sources(ctx)
		if err != nil || provider == nil || inventory == nil {
			return nil, nil, nil, errors.Join(dataplane.ErrRuntimeInactivity, err)
		}
		return r, provider, inventory, nil
	}
	if !errors.Is(err, dataplane.ErrRuntimeInactivitySourcesMissing) {
		return nil, nil, nil, err
	}
	provider, err := createProvider(ctx)
	return nil, provider, nil, err
}

func retainManagedListInactivitySources(ctx context.Context, existing managedListInactivitySources, firstBind func() error, lookup func() (managedListInactivitySources, error)) (managedListInactivitySources, error) {
	if existing != nil {
		return existing, existing.CheckCurrent(ctx)
	}
	if err := firstBind(); err != nil {
		return nil, err
	}
	r, err := lookup()
	if err != nil || r == nil {
		return nil, errors.Join(dataplane.ErrRuntimeInactivity, err)
	}
	return r, r.CheckCurrent(ctx)
}
