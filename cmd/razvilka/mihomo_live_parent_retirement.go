package main

import (
	"context"
	"errors"
	"log"
	"path/filepath"
	"time"

	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/engineconfig"
	"github.com/ArtixSx/razvilka/internal/installpath"
	"github.com/ArtixSx/razvilka/internal/operationgate"
	"github.com/ArtixSx/razvilka/internal/privaterestore"
	"github.com/ArtixSx/razvilka/internal/updatecheck"
)

// Main dispatches before opening any Store or starting workers. The genuine
// five private lifetimes exclude another daemon; the original active execution
// remains an updater fence until every native cleanup and terminal pair ACK.
func runMihomoLiveParentRetirementCLI(ctx context.Context, paths offlineNFQWS2StopPaths, controlRoot string) (result dataplane.Execution, resultErr error) {
	if !mihomoLiveParentRetirementCLIRequested() || bootRetirementCLIFlagError() != nil {
		return result, mihomoLiveBootFailed("flags", nil)
	}
	if ctx == nil {
		return result, mihomoLiveBootFailed("context", nil)
	}
	if err := ctx.Err(); err != nil {
		return result, mihomoLiveBootFailed("context", err)
	}
	if deadline, finite := ctx.Deadline(); !finite || !time.Now().Before(deadline) {
		return result, mihomoLiveBootFailed("context", ctx.Err())
	}
	for _, path := range []string{paths.config, paths.customServices, paths.devices, paths.stage, paths.backups, paths.warp, paths.dataplane, paths.dns, paths.strategyLab, controlRoot} {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return result, mihomoLiveBootFailed("paths", nil)
		}
	}
	// The existing genuine fleet scanner is bound to this installation. A
	// different runtime root cannot borrow its reader capability by matching DTOs.
	if paths.dataplane != filepath.Join(installpath.State, "dataplane") {
		return result, mihomoLiveBootFailed("dataplane-fleet-binding", nil)
	}
	var gate operationgate.Gate
	held, release, err := gate.ExclusiveContext(ctx)
	if err != nil {
		return result, mihomoLiveBootFailed("operation", err)
	}
	defer release()
	ctx = held // Enter the five-set with this EXACT original operation context.
	components, err := configuredComponents(paths.componentState, paths.componentBin, paths.componentInit, paths.componentRepo, paths.componentInfo)
	if err != nil {
		return result, mihomoLiveBootFailed("component-paths", err)
	}
	leases, _, err := openOfflineRuntimeLeases(ctx, paths, privaterestore.OpenForOfflineServiceControl)
	if err != nil {
		return result, mihomoLiveBootFailed("private-recovery", err)
	}
	defer func() {
		resultErr = errors.Join(resultErr, leases.Close())
		if resultErr != nil {
			result = dataplane.Execution{}
		}
	}()
	configuration, err := openMihomoLiveColdConfiguration(ctx, paths.config)
	if err != nil {
		return result, mihomoLiveBootFailed("existing-config", err)
	}
	defer func() {
		resultErr = errors.Join(resultErr, configuration.Close())
		if resultErr != nil {
			result = dataplane.Execution{}
		}
	}()
	err = privaterestore.WithOfflineServiceControlSet(ctx, paths.config, leases.coordinators, func(c context.Context, private *privaterestore.OfflineServiceControlSet) (err error) {
		if c != ctx {
			return dataplane.ErrMihomoLiveRetirement
		}
		if err := configuration.Current(c); err != nil {
			return err
		}
		control, err := gate.ReviewControlEpoch(c, controlRoot)
		if err != nil {
			return mihomoLiveBootFailed("control", err)
		}
		defer func() { err = errors.Join(err, control.Close()) }()
		cleanup, err := control.ReviewExclusiveCleanup(c)
		if err != nil {
			return mihomoLiveBootFailed("cleanup-operation", err)
		}
		history := updatecheck.NewExecutionHistoryAdmission(dataplane.InspectRetainedExecutionReadVersion)
		if err := history.CheckWrite(c, 8); err != nil {
			return mihomoLiveBootFailed("reader-fleet", err)
		}
		manager, err := newColdDataplaneManager(c, paths.dataplane, engineconfig.New(paths.stage, paths.backups), paths.config, components)
		if err != nil {
			return mihomoLiveBootFailed("cold-manager", err)
		}
		if err := registerScopedDNS(manager, nil); err != nil {
			return mihomoLiveBootFailed("dns-owner", err)
		}
		bound, closeSources, sourceErr := mihomoColdRuntimeSourcesBound(c, func() (*dataplane.Manager, error) { return manager, nil }, paths.dns)
		if closeSources != nil {
			defer func() { err = errors.Join(err, closeSources()) }()
		}
		if sourceErr != nil || bound != manager || closeSources == nil {
			return mihomoLiveBootFailed("cold-source", sourceErr)
		}
		err = manager.WithMihomoSameBootRetirement(c, *retireMihomoLiveParentPlan, *retireMihomoLiveParentDigest, private, control, cleanup, controlRoot, history, func(original context.Context, recovery *dataplane.MihomoSameBootRetirement) error {
			var attemptErr error
			result, attemptErr = recovery.Run(original)
			if errors.Is(attemptErr, dataplane.ErrMihomoSameBootRetainedRetry) && original.Err() == nil {
				// Exactly one explicit original-owner retry, within the SAME
				// aggregate deadline and five leases. Never retry generic errors.
				log.Print("Mihomo same-boot: retrying retained cleanup acknowledgment")
				result, attemptErr = recovery.Retry(original)
			}
			return attemptErr
		})
		return errors.Join(err, configuration.Current(c), control.CurrentForCleanupOperation(c, cleanup), history.CheckWrite(c, 8))
	})
	if err != nil {
		return dataplane.Execution{}, mihomoLiveBootFailed("retirement", err)
	}
	return result, nil
}
