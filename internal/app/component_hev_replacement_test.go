package app

import (
	"context"
	"github.com/ArtixSx/razvilka/internal/components"
	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/netidentity"
	"os"
	"path/filepath"
	"testing"
)

func TestHEVReplacementRequiresOriginalRegistryAndReportsRegistrationOnly(t *testing.T) {
	a := managedNFQInitialControlFixture(t)
	if _, err := a.updateHEV(context.Background()); err == nil {
		t.Fatal("unconfigured replacement admitted")
	}
	if _, err := os.Stat(filepath.Join(a.Components.StateDir, "hev-release-v1")); !os.IsNotExist(err) {
		t.Fatal("refused update created journal", err)
	}
	a.Dataplane = dataplane.New(t.TempDir())
	if err := a.ConfigureMihomoProbe(netidentity.NewProcProvider()); err != nil {
		t.Fatal(err)
	}
	operation := a.runtimeLifecycle("hev").Operations["package_update"]
	if operation.Registration != "registered" || operation.Available != nil {
		t.Fatal("registration became permission", operation)
	}
	for _, name := range []string{"live_apply", "live_health", "native_validation"} {
		if a.runtimeLifecycle("hev").Operations[name].Registration != "absent" {
			t.Fatal("replacement invented runtime proof", name)
		}
	}
	a.Components = components.New()
	if a.runtimeLifecycle("hev").Operations["package_update"].Registration != "absent" {
		t.Fatal("foreign components retained update registration")
	}
}
