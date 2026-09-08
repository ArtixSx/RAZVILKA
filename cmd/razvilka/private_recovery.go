package main

import (
	"context"
	"path/filepath"
	"time"

	"github.com/ArtixSx/razvilka/internal/privaterestore"
	"github.com/ArtixSx/razvilka/internal/restorejournal"
)

func preparePrivateRecovery(configPath, customPath, devicesPath, stageRoot, providerOverride string) (*privaterestore.Coordinator, restorejournal.Outcome, error) {
	providerRoot, err := cloudflareStorePath(configPath, providerOverride)
	if err != nil {
		return nil, restorejournal.Blocked, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	return privaterestore.Open(ctx, privaterestore.Layout{
		Config: configPath, CustomServices: customPath, Devices: devicesPath, StageRoot: stageRoot, ProviderRoot: providerRoot,
		// Intentionally not an HTTP field or a separate CLI override. Two new
		// servers sharing this config directory must share the lifetime lease.
		JournalRoot: filepath.Join(filepath.Dir(configPath), "private-restore"),
	})
}

// prepareNodePrivateRecovery uses a new journal directory. Startup keeps the
// legacy coordinator leased too, so an older binary cannot mutate the same
// stores concurrently. Any old pending transaction is settled first.
func prepareNodePrivateRecovery(configPath, customPath, devicesPath, stageRoot, providerOverride, nodeOverride string) (*privaterestore.Coordinator, restorejournal.Outcome, error) {
	providerRoot, err := cloudflareStorePath(configPath, providerOverride)
	if err != nil {
		return nil, restorejournal.Blocked, err
	}
	nodeRoot, err := nodeStorePath(configPath, nodeOverride)
	if err != nil {
		return nil, restorejournal.Blocked, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	return privaterestore.Open(ctx, privaterestore.Layout{
		Config: configPath, CustomServices: customPath, Devices: devicesPath, StageRoot: stageRoot,
		ProviderRoot: providerRoot, NodeRoot: nodeRoot,
		JournalRoot: filepath.Join(filepath.Dir(configPath), "private-restore-nodes-v1"),
	})
}

// privateRecoveryLeases retains every older journal protocol's instance lease.
// Recovery is settled in generation order before the new scope is opened.
type privateRecoveryLeases struct{ coordinators []*privaterestore.Coordinator }

func (g *privateRecoveryLeases) Close() error {
	var failure error
	for i := len(g.coordinators) - 1; i >= 0; i-- {
		if err := g.coordinators[i].Close(); err != nil {
			failure = err
		}
	}
	return failure
}
func (g *privateRecoveryLeases) StartRuntime() error {
	for _, c := range g.coordinators {
		if err := c.StartRuntime(); err != nil {
			return err
		}
	}
	return nil
}

func prepareNativePrivateRecovery(configPath, customPath, devicesPath, stageRoot, providerOverride, nodeOverride, warpRoot string) (*privaterestore.Coordinator, restorejournal.Outcome, error) {
	providerRoot, err := cloudflareStorePath(configPath, providerOverride)
	if err != nil {
		return nil, restorejournal.Blocked, err
	}
	nodeRoot, err := nodeStorePath(configPath, nodeOverride)
	if err != nil {
		return nil, restorejournal.Blocked, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	return privaterestore.Open(ctx, privaterestore.Layout{Config: configPath, CustomServices: customPath, Devices: devicesPath, StageRoot: stageRoot, ProviderRoot: providerRoot, NodeRoot: nodeRoot, WarpRoot: warpRoot, JournalRoot: filepath.Join(filepath.Dir(configPath), "private-restore-native-v1")})
}

func prepareFeedPrivateRecovery(configPath, customPath, devicesPath, stageRoot, providerOverride, nodeOverride, warpRoot string) (*privaterestore.Coordinator, restorejournal.Outcome, error) {
	providerRoot, err := cloudflareStorePath(configPath, providerOverride)
	if err != nil {
		return nil, restorejournal.Blocked, err
	}
	nodeRoot, err := nodeStorePath(configPath, nodeOverride)
	if err != nil {
		return nil, restorejournal.Blocked, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	return privaterestore.Open(ctx, privaterestore.Layout{Config: configPath, CustomServices: customPath, Devices: devicesPath, StageRoot: stageRoot, ProviderRoot: providerRoot, NodeRoot: nodeRoot, WarpRoot: warpRoot, FeedRoot: filepath.Join(filepath.Dir(configPath), "subscriptions-private"), JournalRoot: filepath.Join(filepath.Dir(configPath), "private-restore-feeds-v1")})
}

func preparePrivateRecoveries(configPath, customPath, devicesPath, stageRoot, providerOverride, nodeOverride string, warpOverride ...string) (*privateRecoveryLeases, *privaterestore.Coordinator, restorejournal.Outcome, restorejournal.Outcome, error) {
	legacy, legacyOutcome, err := preparePrivateRecovery(configPath, customPath, devicesPath, stageRoot, providerOverride)
	if err != nil {
		return nil, nil, restorejournal.Blocked, restorejournal.Blocked, err
	}
	current, currentOutcome, err := prepareNodePrivateRecovery(configPath, customPath, devicesPath, stageRoot, providerOverride, nodeOverride)
	if err != nil {
		_ = legacy.Close()
		return nil, nil, legacyOutcome, restorejournal.Blocked, err
	}
	leas := &privateRecoveryLeases{coordinators: []*privaterestore.Coordinator{legacy}}
	if len(warpOverride) == 0 {
		return leas, current, legacyOutcome, currentOutcome, nil
	}
	if len(warpOverride) != 1 || warpOverride[0] == "" {
		current.Close()
		leas.Close()
		return nil, nil, restorejournal.Blocked, restorejournal.Blocked, restorejournal.ErrInvalid
	}
	leas.coordinators = append(leas.coordinators, current)
	native, nativeOutcome, err := prepareNativePrivateRecovery(configPath, customPath, devicesPath, stageRoot, providerOverride, nodeOverride, warpOverride[0])
	if err != nil {
		leas.Close()
		return nil, nil, legacyOutcome, restorejournal.Blocked, err
	}
	if currentOutcome != restorejournal.Clean {
		legacyOutcome = currentOutcome
	}
	leas.coordinators = append(leas.coordinators, native)
	feeds, feedOutcome, err := prepareFeedPrivateRecovery(configPath, customPath, devicesPath, stageRoot, providerOverride, nodeOverride, warpOverride[0])
	if err != nil {
		leas.Close()
		return nil, nil, legacyOutcome, restorejournal.Blocked, err
	}
	if nativeOutcome != restorejournal.Clean {
		legacyOutcome = nativeOutcome
	}
	return leas, feeds, legacyOutcome, feedOutcome, nil
}
