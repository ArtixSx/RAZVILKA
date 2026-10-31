package app

import (
	"context"
	"os"
	"testing"
	"time"
)

func TestMihomoInstallRequiresConfiguredFleetBeforeCacheEffects(t *testing.T) {
	a := managedNFQInitialControlFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := a.installMihomo(ctx); err == nil {
		t.Fatal("custom root bypassed actual controller fleet")
	}
	if _, err := os.Stat(a.Components.StateDir + "/mihomo-artifacts-v1"); !os.IsNotExist(err) {
		t.Fatal("reader refusal created artifact cache", err)
	}
}

func TestMihomoLifecycleSeparatesInstallerAndPackageRecoveryFromRuntime(t *testing.T) {
	a := managedNFQInitialControlFixture(t)
	operations := a.runtimeLifecycle("mihomo").Operations
	for _, name := range []string{"installer", "package_recovery"} {
		if operations[name].Registration != "registered" || operations[name].Available != nil {
			t.Fatal("actual component pipeline hidden or readiness invented", name, operations[name])
		}
	}
	for _, name := range []string{"native_validation", "live_apply", "live_health", "recovery", "rollback", "package_update"} {
		if operations[name].Registration != "absent" {
			t.Fatal("installer invented standalone runtime", name, operations[name])
		}
	}
}
