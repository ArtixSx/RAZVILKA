//go:build linux && amd64 && razvilka_native_fixture

package dataplane

import "testing"

// Test-only historical intent fixture. It exports no observer, native process,
// original lease or cleanup capability to the external integration test.
func MihomoColdHistoricalFixtureForExternalTest(t *testing.T) (*Manager, Execution) {
	m, _, e, _, _, _ := mihomoLiveColdRetirementFixture(t)
	return m, e
}
