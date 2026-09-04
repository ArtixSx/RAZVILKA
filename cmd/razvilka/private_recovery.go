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

func preparePrivateRecoveries(configPath, customPath, devicesPath, stageRoot, providerOverride, nodeOverride string) (*privaterestore.Coordinator, *privaterestore.Coordinator, restorejournal.Outcome, restorejournal.Outcome, error) {
	legacy, legacyOutcome, err := preparePrivateRecovery(configPath, customPath, devicesPath, stageRoot, providerOverride)
	if err != nil {
		return nil, nil, restorejournal.Blocked, restorejournal.Blocked, err
	}
	current, currentOutcome, err := prepareNodePrivateRecovery(configPath, customPath, devicesPath, stageRoot, providerOverride, nodeOverride)
	if err != nil {
		_ = legacy.Close()
		return nil, nil, legacyOutcome, restorejournal.Blocked, err
	}
	return legacy, current, legacyOutcome, currentOutcome, nil
}
