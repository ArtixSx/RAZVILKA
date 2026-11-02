//go:build linux && amd64 && razvilka_native_fixture

package dataplane

import (
	"encoding/json"
	"os"
	"path/filepath"
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
	if os.Getenv("RAZVILKA_MIHOMO_COLD_SOURCE_NATIVE") != "1" {
		t.Skip("explicit disposable export only")
	}
	work := os.Getenv("RAZVILKA_MANAGED_PROBE_FIXTURE_WORK")
	if !filepath.IsAbs(work) || filepath.Clean(work) != os.TempDir() {
		t.Fatal("private fixture workspace required")
	}
	m, _, _, _, _, _ := mihomoLiveColdRetirementFixture(t)
	files := map[string][]byte{}
	for _, name := range []string{"latest-execution.json", "latest-plan.json"} {
		data, err := os.ReadFile(filepath.Join(m.StateRoot, name))
		if err != nil {
			t.Fatal(err)
		}
		files[name] = data
	}
	raw, err := json.Marshal(files)
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(filepath.Join(work, "mihomo-cold-history.json"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		t.Fatal(err)
	}
	_, writeErr := f.Write(raw)
	closeErr := f.Close()
	if writeErr != nil || closeErr != nil {
		t.Fatal(writeErr, closeErr)
	}
}
