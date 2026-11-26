//go:build linux && amd64 && razvilka_native_fixture

package dataplane

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Test-only historical intent fixture. It exports no observer, native process,
// original lease or cleanup capability to the external integration test.
func MihomoColdHistoricalFixtureForExternalTest(t *testing.T) (*Manager, Execution) {
	m, _, e, _, _, _ := mihomoLiveColdRetirementFixture(t)
	return m, e
}

// Emits only inert modeled history for the subsequent standalone CLI test.
// No process, provider, callback or original descriptor crosses this boundary.
func TestMihomoLiveColdExportNativeHistoricalIntent(t *testing.T) {
	exportMihomoColdNativeHistory(t, false)
}
func TestMihomoLiveColdHealth9ExportNativeHistoricalIntent(t *testing.T) {
	exportMihomoColdNativeHistory(t, true)
}
func exportMihomoColdNativeHistory(t *testing.T, health9 bool) {
	if os.Getenv("RAZVILKA_MIHOMO_COLD_SOURCE_NATIVE") != "1" {
		t.Skip("explicit disposable export only")
	}
	work := os.Getenv("RAZVILKA_MANAGED_PROBE_FIXTURE_WORK")
	if !filepath.IsAbs(work) || filepath.Clean(work) != os.TempDir() {
		t.Fatal("private fixture workspace required")
	}
	m, _, original, _, _, _ := mihomoLiveColdRetirementFixture(t)
	files := map[string][]byte{}
	for _, name := range []string{"latest-execution.json", "latest-plan.json"} {
		data, err := os.ReadFile(filepath.Join(m.StateRoot, name))
		if err != nil {
			t.Fatal(err)
		}
		files[name] = data
	}
	name := "mihomo-cold-history.json"
	if health9 {
		// Historical settled operation is documentary model input only.
		original.State, original.FinishedAt = "committed", original.StartedAt
		original.Resources[0].State, original.Resources[0].Phase = "active", "active"
		original.Resources[0].MihomoLive.Observation = &MihomoLiveRuntimeObservation{Schema: 1, SidecarReceiptVersion: 1, SidecarReceiptSHA256: strings.Repeat("a", 64)}
		for n := range original.Steps {
			original.Steps[n].State = "passed"
			original.Steps[n].FinishedAt = original.StartedAt
		}
		before, err := json.Marshal(original)
		if err != nil {
			t.Fatal(err)
		}
		original.MihomoLiveHealthOperation = &ExecutionMihomoLiveHealthOperation{Schema: 1, ID: strings.Repeat("b", 64), PlanID: original.PlanID, PlanDigest: original.Digest, BeforeSHA256: nodeDefaultSourceMaterialHash(before), Phase: "settled"}
		if err := validateExecutionResources(original, true); err != nil {
			t.Fatal("modeled settled9 history", err)
		}
		files["latest-execution.json"], err = json.Marshal(original)
		if err != nil {
			t.Fatal(err)
		}
		name = "mihomo-cold-health9-history.json"
	}
	raw, err := json.Marshal(files)
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(filepath.Join(work, name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		t.Fatal(err)
	}
	_, writeErr := f.Write(raw)
	closeErr := f.Close()
	if writeErr != nil || closeErr != nil {
		t.Fatal(writeErr, closeErr)
	}
}
