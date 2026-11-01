package main

import (
	"bytes"
	"context"
	"errors"
	"os"

	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/privaterestore"
)

// Reuse the existing idle-only offline lease acquisition: no private restore,
// defaults, credentials, Store handover, runtime or network mutation.
func runMihomoBootRetirementCLI(ctx context.Context, paths offlineNFQWS2StopPaths) (result dataplane.Execution, resultErr error) {
	if !mihomoBootRetirementCLIRequested() || bootRetirementCLIFlagError() != nil {
		return result, dataplane.ErrMihomoProbeRetirement
	}
	leases, _, err := openOfflineRuntimeLeases(ctx, paths, privaterestore.OpenForOfflineServiceControl)
	if err != nil {
		return result, dataplane.ErrMihomoProbeRetirement
	}
	defer func() {
		resultErr = errors.Join(resultErr, leases.Close())
		if resultErr != nil {
			result = dataplane.Execution{}
		}
	}()
	config, err := os.ReadFile(paths.config)
	if err != nil {
		return result, dataplane.ErrMihomoProbeRetirement
	}
	defer clear(config)
	current := func(c context.Context) error {
		if c != ctx || c.Err() != nil {
			return dataplane.ErrMihomoProbeRetirement
		}
		raw, err := os.ReadFile(paths.config)
		defer clear(raw)
		if err != nil || !bytes.Equal(raw, config) {
			return dataplane.ErrMihomoProbeRetirement
		}
		return nil
	}
	var hold func(int) error
	hold = func(i int) error {
		if i == len(leases.coordinators) {
			result, err = dataplane.New(paths.dataplane).RetireMihomoProbeAfterBoot(ctx, *retireMihomoBootPlan, *retireMihomoBootDigest, current)
			return err
		}
		return leases.coordinators[i].WithOfflineServiceControl(ctx, paths.config, func(context.Context) error { return hold(i + 1) })
	}
	if err := hold(0); err != nil {
		return result, errors.Join(dataplane.ErrMihomoProbeRetirement, err)
	}
	return result, nil
}
