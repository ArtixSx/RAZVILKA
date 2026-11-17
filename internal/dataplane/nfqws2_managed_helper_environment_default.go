//go:build !linux || !razvilka_native_fixture || !race

package dataplane

// Ordinary builds never consult the diagnostic flag or change the fixed helper
// environment. The native race experiment is absent from these binaries.
func nfqws2ManagedHelperEnvironment(original []string) ([]string, error) {
	return original, nil
}
