package app

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/ArtixSx/razvilka/internal/components"
	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/netidentity"
)

func TestMihomoReplacementNeedsOriginalRegistryAndNeverClaimsReadiness(t *testing.T) {
	a := managedNFQInitialControlFixture(t)
	if _, err := a.updateMihomo(context.Background()); err == nil {
		t.Fatal("unconfigured replacement admitted")
	}
	if _, err := os.Stat(filepath.Join(a.Components.StateDir, "mihomo-artifacts-v1")); !os.IsNotExist(err) {
		t.Fatal("refused update created artifact cache", err)
	}
	a.Dataplane = dataplane.New(t.TempDir())
	if err := a.ConfigureMihomoProbe(netidentity.NewProcProvider()); err != nil {
		t.Fatal(err)
	}
	operation := a.runtimeLifecycle("mihomo").Operations["package_update"]
	if operation.Registration != "registered" || operation.Available != nil {
		t.Fatal("original registration is not live readiness", operation)
	}
	if a.runtimeLifecycle("mihomo").Operations["live_apply"].Registration != "absent" {
		t.Fatal("package replacement invented live apply")
	}
	a.Components = components.New()
	if a.runtimeLifecycle("mihomo").Operations["package_update"].Registration != "absent" {
		t.Fatal("foreign configured component owner granted update registration")
	}
}
