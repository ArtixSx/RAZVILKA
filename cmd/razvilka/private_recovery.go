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
