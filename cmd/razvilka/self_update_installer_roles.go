package main

import (
	"context"

	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/updatecheck"
)

func bindSelfUpdateInstallerRoles(ctx context.Context, manager *dataplane.Manager, adapter *updatecheck.SelfUpdateFileAdapter, id string) error {
	if manager == nil || adapter == nil {
		return dataplane.ErrRuntimeInactivity
	}
	count := 0
	for _, registered := range manager.Adapters {
		if dns, ok := registered.(*dataplane.ScopedDNSAdapter); ok {
			if err := dns.BindInstallerControllerRoles(ctx, adapter, id); err != nil {
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
