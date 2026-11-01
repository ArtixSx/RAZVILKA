//go:build linux && (amd64 || arm64) && !razvilka_native_fixture

package startuptools

// Ordinary builds collect no fixture metrics or state.
func noteVersionMetadataAttempt(*heldReview) {}
