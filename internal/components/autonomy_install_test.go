package components

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestInstallAbsentUsesOrdinaryVerifiedPackagePath(t *testing.T) {
	manager, runner := singBoxManagerFixture(t)
	ctx := context.Background()
	guard := func(context.Context) error { return nil }
	result, err := manager.InstallAbsent(ctx, "sing-box", guard)
	if err != nil || !result.OK || result.Action != "install" {
		t.Fatalf("missing component was not installed: %+v, %v", result, err)
	}
	init, err := os.ReadFile(filepath.Join(runner.initDir, singBoxInitName))
	if err != nil || !strings.Contains(string(init), "ENABLED=no") {
		t.Fatalf("package init was not left inert: %s, %v", init, err)
	}
	if _, err := manager.InstallAbsent(ctx, "sing-box", guard); !errors.Is(err, ErrComponentAlreadyInstalled) {
		t.Fatalf("repeat install did not stop at installed state: %v", err)
	}
	if slices.Contains(runner.calls, "upgrade sing-box-go") {
		t.Fatalf("first-install permission ran an upgrade: %v", runner.calls)
	}
}

func TestInstallAbsentRechecksAuthorityBeforePackageCommand(t *testing.T) {
	manager, runner := singBoxManagerFixture(t)
	revoked := errors.New("service revision changed")
	guard := func(context.Context) error {
		if len(runner.calls) >= 2 {
			return revoked
		}
		return nil
	}
	_, err := manager.InstallAbsent(context.Background(), "sing-box", guard)
	if !errors.Is(err, revoked) || !errors.Is(err, ErrNoMutation) || slices.Contains(runner.calls, "install sing-box-go") {
		t.Fatalf("stale install reached opkg: %v, %v", err, runner.calls)
	}
}

func TestInstallAbsentXrayKeepsInstalledSingBoxDependency(t *testing.T) {
	runner := &fakeRunner{output: map[string]string{"install": "installed", "list-installed": "sing-box-go - 1.13.3-2 - existing shared core\n"}}
	manager := &Manager{
		Opkg: "fixture-opkg", Runner: runner, StateDir: t.TempDir(), InitDir: t.TempDir(),
		AdmitXrayCoreWrite: admitTestXray,
	}
	result, err := manager.InstallAbsent(context.Background(), "xray", func(context.Context) error { return nil })
	if err != nil || !result.OK || result.Action != "install" {
		t.Fatalf("missing Xray was not installed: %+v, %v", result, err)
	}
	for _, args := range runner.calls {
		if len(args) >= 3 && (args[1] == "upgrade" || args[2] == "sing-box-go") {
			t.Fatalf("initial Xray install changed an existing Sing-box dependency: %v", runner.calls)
		}
	}
}
