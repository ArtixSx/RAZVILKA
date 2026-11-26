package main

import (
	"context"
	"errors"

	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/updatecheck"
)

func bindSelfUpdateInstallerRoles(ctx context.Context, manager *dataplane.Manager, adapter *updatecheck.SelfUpdateFileAdapter, id string) error {
	if manager == nil || adapter == nil {
		return dataplane.ErrRuntimeInactivity
	}
	original, err := updatecheck.OriginalOrdinaryInstallerControllerAdapter(ctx, id)
	if err != nil || original != nil && original != adapter {
		return errors.Join(dataplane.ErrRuntimeInactivity, err)
	}
	ordinary := original != nil
	if !ordinary {
		ordinary, err = adapter.OrdinaryInstallerControllerReview(ctx, id)
		if err != nil {
			return errors.Join(dataplane.ErrRuntimeInactivity, err)
		}
	}
	count := 0
	for _, registered := range manager.Adapters {
		if dns, ok := registered.(*dataplane.ScopedDNSAdapter); ok {
			var err error
			if ordinary {
				err = dns.BindOrdinaryInstallerControllerRoles(ctx, adapter, id)
			} else {
				err = dns.BindInstallerControllerRoles(ctx, adapter, id)
			}
			if err != nil {
				return err
			}
			count++
		}
	}
	if count != 1 {
		return dataplane.ErrRuntimeInactivity
	}
	return ctx.Err()
}
