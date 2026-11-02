//go:build linux && amd64 && razvilka_native_fixture

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/installpath"
	"github.com/ArtixSx/razvilka/internal/privaterestore"
)

// Actual offline CLI entry, original five private leases, held config and
// production source assembly. Historical prior boot is inert model input;
// native platform classification uses the existing explicitly tagged fixture.
func TestMihomoLiveColdCLINativeHistoricalIntent(t *testing.T) { runMihomoColdNativeCLI(t, false) }
func TestMihomoLiveColdHealth9CLINativeHistoricalIntent(t *testing.T) {
	runMihomoColdNativeCLI(t, true)
}
func runMihomoColdNativeCLI(t *testing.T, health9 bool) {
	if os.Getenv("RAZVILKA_MIHOMO_COLD_SOURCE_NATIVE") != "1" {
		t.Skip("explicit disposable CLI fixture only")
	}
	work := os.Getenv("RAZVILKA_MANAGED_PROBE_FIXTURE_WORK")
	if !filepath.IsAbs(work) || filepath.Clean(work) != os.TempDir() || os.Geteuid() != 0 {
		t.Fatal("private native workspace required")
	}
	name := "mihomo-cold-history.json"
	if health9 {
		name = "mihomo-cold-health9-history.json"
	}
	raw, err := os.ReadFile(filepath.Join(work, name))
	if err != nil || len(raw) > 1<<20 {
		t.Fatal("modeled historical input", err)
	}
	var files map[string][]byte
	if json.Unmarshal(raw, &files) != nil || len(files) != 2 {
		t.Fatal("closed fixture files")
	}
	var original dataplane.Execution
	if json.Unmarshal(files["latest-execution.json"], &original) != nil || len(original.Resources) != 1 || original.Resources[0].MihomoLive == nil {
		t.Fatal("modeled intent")
	}
	base := filepath.Join(t.TempDir(), "private")
	if err := os.Mkdir(base, 0700); err != nil {
		t.Fatal(err)
	}
	paths := offlineStopTestPaths(base)
	if health9 {
		paths.dataplane = filepath.Join(installpath.State, "dataplane")
	}
	write := func(path string, data []byte) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	cfg := config.Default()
	cfg.ProxySidecar = "hev"
	configImage, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	write(paths.config, configImage)
	write(filepath.Join(paths.dataplane, "latest-execution.json"), files["latest-execution.json"])
	write(filepath.Join(paths.dataplane, "transactions", original.PlanID, "execution.json"), files["latest-execution.json"])
	write(filepath.Join(paths.dataplane, "latest-plan.json"), files["latest-plan.json"])
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	leases, _, err := openOfflineRuntimeLeases(ctx, paths, func(c context.Context, l privaterestore.Layout) (*privaterestore.Coordinator, error) {
		o, _, e := privaterestore.Open(c, l)
		return o, e
	})
	if err != nil {
		t.Fatal("fixture initialize original restore generations", err)
	}
	if err := leases.Close(); err != nil {
		t.Fatal(err)
	}
	preserveMihomoLiveRetirementFlags(t)
	*retireMihomoLiveBootPlan, *retireMihomoLiveBootDigest = original.PlanID, original.Digest
	result, err := runMihomoLiveBootRetirementCLI(ctx, paths)
	if err != nil {
		t.Fatal("actual offline CLI", err)
	}
	if result.State != "rolled-back" || result.RollbackVerified || result.PlanID != original.PlanID {
		t.Fatal("wrong terminal result", result.State)
	}
	if health9 {
		got, before := result.MihomoLiveHealthOperation, original.MihomoLiveHealthOperation
		if got == nil || before == nil || got.Phase != "retired" || got.ID != before.ID || got.BeforeSHA256 != before.BeforeSHA256 || got.PlanID != before.PlanID || got.PlanDigest != before.PlanDigest {
			t.Fatal("offline9 header anchors not retained")
		}
		if version, _, err := dataplane.InspectRetainedExecutionReadVersion(ctx, paths.dataplane); err != nil || version != 9 {
			t.Fatal("actual offline terminal scanner lost reader9", version, err)
		}
		t.Log("actual fleet admission + all five CLI leases + fresh native absence + terminal reader9 history passed; original old boot and settled health are modeled")
	}
	current, err := os.ReadFile(paths.config)
	if err != nil || !bytes.Equal(current, configImage) {
		t.Fatal("CLI changed held configuration", err)
	}
	// Actual successful return includes closure of all original lifetime leases.
	check, stop := context.WithTimeout(context.Background(), 10*time.Second)
	defer stop()
	closed, _, err := openOfflineRuntimeLeases(check, paths, privaterestore.OpenForOfflineServiceControl)
	if err != nil {
		t.Fatal("CLI retained a private generation lock", err)
	}
	if len(closed.coordinators) != 5 {
		t.Fatal("not all five generations checked")
	}
	if err := closed.Close(); err != nil {
		t.Fatal(err)
	}
	t.Log("actual offline CLI entry, all five original private leases, unchanged config, complete current native absence and terminal publication passed; historical old boot modeled")
}
