//go:build !linux || !amd64 || !razvilka_native_fixture

package main

import (
	"context"

	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/netidentity"
	"github.com/ArtixSx/razvilka/internal/startuptools"
)

// Ordinary binaries never read fixture environment or accept native-platform
// classification. The existing supported-platform selection remains exact.
type runtimeInactivityNativeFixture struct{}

func runtimeInactivityFixture(context.Context, selfUpdateRuntimePlatformFacts) (*runtimeInactivityNativeFixture, error) {
	return nil, nil
}
func (*runtimeInactivityNativeFixture) Acquire(context.Context, *netidentity.Provider) (*startuptools.Lease, error) {
	return nil, dataplane.ErrRuntimeInactivity
}
func (*runtimeInactivityNativeFixture) Close() error { return nil }
