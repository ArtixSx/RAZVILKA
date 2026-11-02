package main

import (
	"context"
	"errors"
	"path/filepath"
	"time"

	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/engineconfig"
	"github.com/ArtixSx/razvilka/internal/privaterestore"
)

type mihomoLiveBootCLIError struct {
	stage string
	cause error
}

func (e *mihomoLiveBootCLIError) Error() string {
	return "Mihomo live offline retirement refused at " + e.stage
}
func (e *mihomoLiveBootCLIError) Unwrap() error { return e.cause }
func mihomoLiveBootFailed(stage string, err error) error {
	return &mihomoLiveBootCLIError{stage: stage, cause: errors.Join(dataplane.ErrMihomoLiveRetirement, err)}
}

// Idle-only five-generation private leases remain held through actual complete
// cold source admission, metadata publication, and source closing. No ordinary
// Store bootstrap, permission repair, workers or warm runtime is started.
func runMihomoLiveBootRetirementCLI(ctx context.Context, paths offlineNFQWS2StopPaths) (result dataplane.Execution, resultErr error) {
	if !mihomoLiveBootRetirementCLIRequested() || bootRetirementCLIFlagError() != nil {
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
	for _, path := range []string{paths.config, paths.customServices, paths.devices, paths.stage, paths.backups, paths.warp, paths.dataplane, paths.dns} {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return result, mihomoLiveBootFailed("paths", nil)
		}
	}
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
	current := func(c context.Context) error {
		if c == nil {
			return dataplane.ErrMihomoLiveRetirement
		}
		if c != ctx || c.Err() != nil {
			return errors.Join(dataplane.ErrMihomoLiveRetirement, c.Err())
		}
		return configuration.Current(c)
	}
	var held func(int) error
	held = func(index int) error {
		if index < len(leases.coordinators) {
			return leases.coordinators[index].WithOfflineServiceControl(ctx, paths.config, func(context.Context) error { return held(index + 1) })
		}
		return func() (err error) {
			if err := current(ctx); err != nil {
				return mihomoLiveBootFailed("settings-current", err)
			}
			manager, err := newColdDataplaneManager(ctx, paths.dataplane, engineconfig.New(paths.stage, paths.backups), paths.config, components)
			if err != nil {
				return mihomoLiveBootFailed("cold-manager", err)
			}
			if err := registerScopedDNS(manager, nil); err != nil {
				return mihomoLiveBootFailed("dns-owner", err)
			}
			bound, closeSources, sourceErr := runtimeManagerSourcesBound(ctx, func() (*dataplane.Manager, error) { return manager, nil }, paths.dns)
			if closeSources != nil {
				defer func() { err = errors.Join(err, closeSources()) }()
			}
			if sourceErr != nil || bound != manager || closeSources == nil {
				return mihomoLiveBootFailed("cold-source", sourceErr)
			}
			result, err = manager.RetireMihomoLiveAfterBoot(ctx, *retireMihomoLiveBootPlan, *retireMihomoLiveBootDigest, current)
			return errors.Join(err, current(ctx))
		}()
	}
	if err := held(0); err != nil {
		return result, mihomoLiveBootFailed("retirement", err)
	}
	return result, nil
}
