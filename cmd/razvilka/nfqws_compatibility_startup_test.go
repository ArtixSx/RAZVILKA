package main

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/ArtixSx/razvilka/internal/app"
	"github.com/ArtixSx/razvilka/internal/components"
	"github.com/ArtixSx/razvilka/internal/operationgate"
	"github.com/ArtixSx/razvilka/internal/strategylab"
)

func TestManagedNFQCompatibilityStartupMissingInstalledSourceStaysClosed(t *testing.T) {
	manager, err := strategylab.New(filepath.Join(t.TempDir(), "strategy-lab.json"))
	if err != nil {
		t.Fatal(err)
	}
	manager.Validator = strategylab.CompatibleValidator{}
	manager.Executor = nil
	controlRoot := filepath.Join(t.TempDir(), "control")
	if _, err := operationgate.InitializeSelfUpdateControl(context.Background(), controlRoot); err != nil {
		t.Fatal(err)
	}
	owner := components.New()
	owner.StateDir = t.TempDir()
	a := &app.App{StrategyLab: manager, Components: owner, SelfUpdateFiles: &app.SelfUpdateFiles{ControlRoot: controlRoot}}
	t.Cleanup(func() { _ = a.CloseManagedNFQControl() })
	if control, err := configureManagedNFQCompatibility(context.Background(), a); err == nil || control != nil {
		t.Fatal("missing genuine installed receipt configured provider", err)
	}
	validator, ok := manager.Validator.(strategylab.CompatibleValidator)
	if !ok || validator.Provider != nil || validator.TrustedAssets || manager.Executor != nil || a.Operations.Snapshot().Active != 0 {
		t.Fatal("failed startup enabled assets, probing or retained admission")
	}
	if validation := validator.Validate(context.Background(), []string{"--filter-tcp=443"}); validation.Native || validation.OK || validation.Code != "ASSET_REVIEW_REQUIRED" {
		t.Fatal("closed startup fell back to execution", validation.Code)
	}
}
