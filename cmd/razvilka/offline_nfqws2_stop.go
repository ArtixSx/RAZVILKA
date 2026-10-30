package main

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"time"

	"github.com/ArtixSx/razvilka/internal/app"
	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/engineconfig"
	"github.com/ArtixSx/razvilka/internal/installpath"
	"github.com/ArtixSx/razvilka/internal/privaterestore"
)

type offlineNFQWS2StopPaths struct {
	config, customServices, devices, stage, backups string
	cloudflare, nodes, warp, dataplane, dns         string
	componentState, componentBin, componentInit     string
	componentRepo, componentInfo                    string
}

// Keep native and private errors available to callers without printing their
// paths or retained private document contents in a CLI refusal.
type offlineNFQWS2StopCLIError struct {
	stage string
	cause error
}

func (e *offlineNFQWS2StopCLIError) Error() string { return "owned-route Stop refused at " + e.stage }
func (e *offlineNFQWS2StopCLIError) Unwrap() error { return e.cause }

func offlineNFQWS2StopFailed(stage string, cause error) error {
	return &offlineNFQWS2StopCLIError{stage: stage, cause: cause}
}

// The installed explicit Stop keeps every private restore generation leased
// without handing any of them to HTTP/workers. The whole native transaction
// and source closing finish here, before main can print success or exit.
func runOfflineNFQWS2StopCLI(ctx context.Context, paths offlineNFQWS2StopPaths) (result app.OfflineNFQWS2StopResult, resultErr error) {
	if ctx == nil || ctx.Err() != nil {
		return result, offlineNFQWS2StopFailed("context", dataplane.ErrReviewChanged)
	}
	if deadline, finite := ctx.Deadline(); !finite || !time.Now().Before(deadline) {
		return result, offlineNFQWS2StopFailed("context", dataplane.ErrReviewChanged)
	}
	for _, path := range []string{paths.config, paths.customServices, paths.devices, paths.stage, paths.backups, paths.warp, paths.dataplane, paths.dns} {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path || strings.TrimSpace(path) != path {
			return result, offlineNFQWS2StopFailed("paths", dataplane.ErrReviewChanged)
		}
	}
	componentManager, err := configuredComponents(paths.componentState, paths.componentBin, paths.componentInit, paths.componentRepo, paths.componentInfo)
	if err != nil {
		return result, offlineNFQWS2StopFailed("component-paths", err)
	}
	leases, current, err := openOfflineNFQWS2StopLeases(ctx, paths)
	if err != nil {
		return result, offlineNFQWS2StopFailed("private-recovery", err)
	}
	defer func() {
		if err := leases.Close(); err != nil {
			resultErr = errors.Join(resultErr, offlineNFQWS2StopFailed("private-recovery-close", err))
		}
		if resultErr != nil {
			result = app.OfflineNFQWS2StopResult{}
		}
	}()
	if err := ctx.Err(); err != nil {
		return result, offlineNFQWS2StopFailed("context", err)
	}
	// Recovery owns the disk before the Store is opened. Missing settings are
	// an error; this command must not manufacture a new configuration.
	store, err := config.LoadExisting(paths.config)
	if err != nil {
		return result, offlineNFQWS2StopFailed("existing-config", err)
	}
	manager, err := newDataplaneManager(paths.dataplane, engineconfig.New(paths.stage, paths.backups))
	if err != nil {
		return result, offlineNFQWS2StopFailed("manager", err)
	}
	if err := registerScopedDNS(manager, nil); err != nil {
		return result, offlineNFQWS2StopFailed("dns-owner", err)
	}
	if err := manager.ConfigureNFQWSStockNative(componentManager); err != nil {
		return result, offlineNFQWS2StopFailed("stock-owner", err)
	}
	bound, closeSources, err := runtimeManagerSourcesBound(ctx, func() (*dataplane.Manager, error) { return manager, nil }, paths.dns)
	if closeSources != nil {
		defer func() {
			if err := closeSources(); err != nil {
				resultErr = errors.Join(resultErr, offlineNFQWS2StopFailed("source-close", err))
			}
		}()
	}
	if err != nil || bound != manager || closeSources == nil {
		return result, offlineNFQWS2StopFailed("runtime-source/"+selfUpdateRuntimeManagerFailureStage(err), errors.Join(dataplane.ErrRuntimeInactivity, err))
	}
	result, err = app.StopOwnedNFQWS2Routes(ctx, current, manager, store, paths.config, paths.dns)
	if err != nil {
		return result, offlineNFQWS2StopFailed("transaction", err)
	}
	return result, nil
}

// Ordinary private restore opening may replay a prepared target image. That
// is forbidden beside an explicit Stop's comparison WAL. Acquire each old
// protocol's actual lifetime lease in the same order as daemon startup, but
// require idle metadata without recovering or opening any target Store.
func openOfflineNFQWS2StopLeases(ctx context.Context, paths offlineNFQWS2StopPaths) (*privateRecoveryLeases, *privaterestore.Coordinator, error) {
	providerRoot, err := cloudflareStorePath(paths.config, paths.cloudflare)
	if err != nil {
		return nil, nil, err
	}
	nodeRoot, err := nodeStorePath(paths.config, paths.nodes)
	if err != nil {
		return nil, nil, err
	}
	base := filepath.Dir(paths.config)
	layout := privaterestore.Layout{Config: paths.config, CustomServices: paths.customServices, Devices: paths.devices, StageRoot: paths.stage, ProviderRoot: providerRoot}
	leases := &privateRecoveryLeases{}
	var current *privaterestore.Coordinator
	for i, generation := range []string{"private-restore", "private-restore-nodes-v1", "private-restore-native-v1", "private-restore-feeds-v1"} {
		layout.JournalRoot = filepath.Join(base, generation)
		if i >= 1 {
			layout.NodeRoot = nodeRoot
		}
		if i >= 2 {
			layout.WarpRoot = paths.warp
		}
		if i >= 3 {
			layout.FeedRoot = filepath.Join(base, "subscriptions-private")
		}
		current, err = privaterestore.OpenForOfflineNFQWS2Stop(ctx, layout)
		if err != nil {
			return nil, nil, errors.Join(err, leases.Close())
		}
		leases.coordinators = append(leases.coordinators, current)
	}
	return leases, current, nil
}

// These commands do not cross a mutation boundary. Flag modes are classified
// after parsing in main, where an explicit dataplane root is available.
func offlineNFQWS2StopReadOnlyCommand(args []string) bool {
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		return true
	}
	switch strings.ToLower(strings.TrimSpace(args[0])) {
	case "version", "v", "status", "s", "doctor", "diag", "d", "help", "h":
		return true
	case "components", "bypasses":
		return len(args) == 1
	case "component":
		return len(args) == 4 && args[1] == "plan"
	case "self-update-files":
		return len(args) == 2 && args[1] == "current"
	default:
		return false
	}
}

func checkOfflineNFQWS2StopCommand(args []string) error {
	if offlineNFQWS2StopReadOnlyCommand(args) {
		return nil
	}
	production := selfUpdateDefaultPath(installpath.State + "/dataplane")
	configured := getenv("RAZVILKA_DATAPLANE_STATE", production)
	return checkOfflineNFQWS2StopMutation(configured, false)
}

func checkOfflineNFQWS2StopMutation(configured string, explicitStop bool) error {
	// A state-directory override does not relocate every native package file.
	// Fixed helpers ignore it, and ordinary adapters still share package paths.
	// It must not hide a pending Stop at the fixed installation's state root.
	production := selfUpdateDefaultPath(installpath.State + "/dataplane")
	return checkOfflineNFQWS2StopMutationAt(production, configured, explicitStop)
}

func checkOfflineNFQWS2StopMutationAt(production, configured string, explicitStop bool) error {
	if configured != production || !explicitStop {
		if err := app.CheckOfflineNFQWS2Stop(production); err != nil {
			return err
		}
	}
	if !explicitStop && configured != production {
		return app.CheckOfflineNFQWS2Stop(configured)
	}
	return nil
}
