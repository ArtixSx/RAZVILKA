package main

import (
	"context"
	"errors"
	"runtime"
	"time"

	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/installpath"
	"github.com/ArtixSx/razvilka/internal/netidentity"
	"github.com/ArtixSx/razvilka/internal/startuptools"
	"github.com/ArtixSx/razvilka/internal/updatecheck"
)

type selfUpdateRuntimePlatform uint8

const (
	selfUpdateRuntimeUbuntu70 selfUpdateRuntimePlatform = iota + 1
	selfUpdateRuntimeStockNC1812
)

type selfUpdateRuntimePlatformFacts struct {
	system, arch, release, machine, distribution, version string
	metadataOwner                                         [32]byte
}

// A closed selection of the two reviewed assemblies. These facts neither
// authenticate tools nor prove inactivity; the selected factories do that work.
func selectSelfUpdateRuntimePlatform(f selfUpdateRuntimePlatformFacts) (selfUpdateRuntimePlatform, error) {
	switch {
	case f.system == "Linux" && f.arch == "amd64" && f.machine == "x86_64" &&
		f.release == "7.0.0-38-generic" && f.distribution == "ubuntu" && f.version == "26.04":
		return selfUpdateRuntimeUbuntu70, nil
	case f.system == "Linux" && f.arch == "arm64" && f.machine == "aarch64" && f.release == "4.9-ndm-5":
		// The original factory must still verify the complete NC1812 build.
		return selfUpdateRuntimeStockNC1812, nil
	default:
		return 0, dataplane.ErrRuntimeInactivity
	}
}

type selfUpdateRuntimeSourceFailure struct {
	stage string
	cause error
}

func (e *selfUpdateRuntimeSourceFailure) Error() string {
	return "runtime source refused; category=" + selfUpdateRuntimeManagerFailureStage(e)
}
func (e *selfUpdateRuntimeSourceFailure) Unwrap() error { return e.cause }

func selfUpdateRuntimeSourceFailed(stage string, cause error) error {
	return &selfUpdateRuntimeSourceFailure{stage, errors.Join(dataplane.ErrRuntimeInactivity, cause)}
}

func selfUpdateRuntimeManagerFailureStage(err error) string {
	var failure *selfUpdateRuntimeSourceFailure
	if errors.As(err, &failure) {
		switch failure.stage {
		case "manager-context", "manager-platform", "manager-registry", "network-provider", "tools-acquire", "tools-inventory", "backend-inventory", "inactivity-owner-bind":
			stage := failure.stage
			if stage == "inactivity-owner-bind" {
				stage = selfUpdateRuntimeBindFailureStage(dataplane.NFQWSRuntimeInactiveStage(err))
			}
			if errors.Is(err, errSelfUpdateRuntimeSourceClose) {
				return updatecheck.RuntimeQuiesceSourceCleanupFailureStage(stage)
			}
			return stage
		}
	}
	return "manager-construction"
}

// Only the actual original constructor error supplies this private branch.
// Unknown branches retain the broad refusal; no Error text or new read is used.
func selfUpdateRuntimeBindFailureStage(nfqStage string) string {
	switch nfqStage {
	case "source", "platform", "coordinates", "identity", "inventory", "closure":
		return "inactivity-owner-bind-nfq-" + nfqStage
	default:
		return "inactivity-owner-bind"
	}
}

var errSelfUpdateRuntimeSourceClose = errors.New("runtime source closure failed")

// Choose one final closed diagnostic after joining the actual source. A joined
// cleanup failure preserves the primary stage in a fixed vocabulary.
func finishSelfUpdateRuntimeQuiesce(stage string, closeSource func() error) string {
	if closeSource == nil || closeSource() != nil {
		return updatecheck.RuntimeQuiesceSourceCleanupFailureStage(stage)
	}
	return stage
}

// Helper ownership ends only after its original complete Deactivate/proof
// operation. No Verify call reacquires tools, replaces the provider or extends
// the original caller deadline.
func selfUpdateRuntimeManagerBound(ctx context.Context) (*dataplane.Manager, func() error, error) {
	return runtimeManagerSourcesBound(ctx, selfUpdateRuntimeManager, selfUpdateDefaultPath(installpath.State+"/dns/state.json"))
}

// The supplied manager is the actual consumer, including offline CLI paths.
// Platform/tool/provider admission and the retained source lifetime are the
// same as the existing self-update assembly; no detached absence is imported.
func runtimeManagerSourcesBound(ctx context.Context, create func() (*dataplane.Manager, error), dnsPath string) (*dataplane.Manager, func() error, error) {
	return runtimeManagerSourcesBoundLifetime(ctx, ctx, create, dnsPath)
}

// Startup bounds acquisition separately from the explicitly owned process
// lifetime. Each subsequent observation still supplies its own finite context
// and rechecks the held tool images and network identity; Close revokes all.
func runtimeManagerSourcesBoundLifetime(ctx, lifetime context.Context, create func() (*dataplane.Manager, error), dnsPath string) (*dataplane.Manager, func() error, error) {
	if ctx == nil || ctx.Err() != nil {
		var cause error
		if ctx != nil {
			cause = ctx.Err()
		}
		return nil, nil, selfUpdateRuntimeSourceFailed("manager-context", cause)
	}
	if lifetime == nil || lifetime.Err() != nil {
		return nil, nil, selfUpdateRuntimeSourceFailed("manager-context", nil)
	}
	if deadline, finite := ctx.Deadline(); !finite || !time.Now().Before(deadline) {
		return nil, nil, selfUpdateRuntimeSourceFailed("manager-context", ctx.Err())
	}
	// Keep the original calling thread across platform selection, source binding
	// and closing selection. Provider observations retain their own bookends.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	facts, err := observeSelfUpdateRuntimePlatform(ctx)
	if err != nil {
		return nil, nil, selfUpdateRuntimeSourceFailed("manager-platform", err)
	}
	platform, err := selectSelfUpdateRuntimePlatform(facts)
	if err != nil {
		return nil, nil, selfUpdateRuntimeSourceFailed("manager-platform", err)
	}
	if create == nil {
		return nil, nil, selfUpdateRuntimeSourceFailed("manager-registry", nil)
	}
	manager, err := create()
	if err != nil {
		return nil, nil, selfUpdateRuntimeSourceFailed("manager-registry", err)
	}
	var provider *netidentity.Provider
	if platform == selfUpdateRuntimeStockNC1812 {
		provider, err = netidentity.NewReviewedStockNC1812Provider(ctx)
	} else {
		provider = netidentity.NewProcProvider()
		_, err = provider.Observe(ctx)
	}
	if err != nil {
		return nil, nil, selfUpdateRuntimeSourceFailed("network-provider", err)
	}
	var tools *startuptools.Lease
	if platform == selfUpdateRuntimeStockNC1812 {
		tools, err = startuptools.AcquireReviewedStockNC1812(lifetime, provider)
	} else {
		tools, err = startuptools.AcquireUbuntuLegacy(lifetime, provider)
	}
	if err != nil {
		return nil, nil, selfUpdateRuntimeSourceFailed("tools-acquire", err)
	}
	closeRefused := func(stage string, cause error) (*dataplane.Manager, func() error, error) {
		if closeErr := tools.Close(); closeErr != nil {
			cause = errors.Join(cause, errSelfUpdateRuntimeSourceClose, closeErr)
		}
		return nil, nil, selfUpdateRuntimeSourceFailed(stage, cause)
	}
	backendTools, err := tools.InventoryTools()
	if err != nil {
		return closeRefused("tools-inventory", err)
	}
	var inventory *dataplane.BackendInventory
	if platform == selfUpdateRuntimeStockNC1812 {
		inventory, err = dataplane.NewReviewedStockNC1812BackendInventory(provider, backendTools)
	} else {
		inventory, err = dataplane.NewBackendInventory(provider, backendTools)
	}
	if err != nil {
		return closeRefused("backend-inventory", err)
	}
	if err := manager.BindRuntimeInactivitySources(ctx, provider, inventory, dnsPath); err != nil {
		return closeRefused("inactivity-owner-bind", err)
	}
	closing, err := observeSelfUpdateRuntimePlatform(ctx)
	if err != nil || closing != facts || ctx.Err() != nil {
		return closeRefused("manager-platform", errors.Join(err, ctx.Err()))
	}
	return manager, tools.Close, nil
}
