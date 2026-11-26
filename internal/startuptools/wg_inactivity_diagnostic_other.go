//go:build !linux || !razvilka_native_fixture

package startuptools

func wgInactivityNativeDiagnostic(_ []string, _, _ *output, _, _ error) {}
